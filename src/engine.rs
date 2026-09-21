//! 脱敏映射室核心引擎：规则裁决、脱敏/稳定 token、加密映射、还原、轮换与审计。

use crate::audit::{
    self, append_entry, verify_chain, AuditEntry, ChainHead, Clock, VerifyReport,
};
use crate::b64;
use crate::crypto::{self, seal, FillBytes};
use crate::fsutil::{atomic_write, read_if_exists};
use crate::keys::{self, Keychain, RotationPhase};
use crate::model::{self, adjudicate, validate_rule, EngineError, EngineResult, Hit, Rule, RuleKind};
use crate::state::{MappingRecord, RedactionRecord, StateFile, TenantState};
use crate::tokens::{self, ParsedToken};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// 轮换崩溃点（仅测试注入使用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    AfterKeyWritten,
    AfterPromoted,
    AfterState,
}

/// 公开 API 使用的数据对象。
#[derive(Debug, Clone, Serialize)]
pub struct RuleView {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub detail: Value,
    pub priority: i32,
    pub stable: bool,
    pub enabled: bool,
    pub rule_version: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleInput {
    pub id: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub pattern: Option<String>,
    pub min: Option<Value>,
    pub max: Option<Value>,
    pub priority: Option<i32>,
    pub stable: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HitView {
    pub rule_id: String,
    pub rule_name: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub priority: i32,
    pub stable: bool,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressedView {
    pub rule_id: String,
    pub rule_name: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub reason: String,
    pub by_rule_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactionOutput {
    pub text: String,
    pub rule_version: u64,
    pub key_generation: u64,
    pub accepted: Vec<HitView>,
    pub suppressed: Vec<SuppressedView>,
    pub token_protected: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreItemOutput {
    pub index: usize,
    pub ok: bool,
    /// 成功时给出原文；失败固定为 null，且不包含任何归属线索。
    pub original: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSummary {
    pub entries: u64,
    pub last_seq: u64,
    pub last_hash: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleMeta {
    pub rule_version: u64,
    pub rules: Vec<RuleView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportBundle {
    pub exported_unix: i64,
    pub tenants: BTreeMap<String, TenantExport>,
    pub audit_summary: AuditSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantExport {
    pub rule_metadata: RuleMeta,
    /// 仅已脱敏文本。
    pub redactions: Vec<RedactionRecord>,
}

pub struct Engine {
    dir: PathBuf,
    state: Mutex<StateFile>,
    keychain: Mutex<Keychain>,
    head: Mutex<ChainHead>,
    clock: Arc<dyn Clock + Send + Sync>,
    rng: Mutex<Box<dyn FillBytes + Send>>,
    /// 测试用：轮换到某阶段后“崩溃”（抛错，模拟掉电）。
    crash: Mutex<Option<CrashPoint>>,
}

const STATE_NAME: &str = "state.json";
const AUDIT_NAME: &str = "audit.log";

fn err_other(s: impl Into<String>) -> EngineError {
    EngineError::Io(s.into())
}

impl Engine {
    fn state_file_path(dir: &Path) -> PathBuf {
        dir.join(STATE_NAME)
    }
    fn audit_path(dir: &Path) -> PathBuf {
        dir.join(AUDIT_NAME)
    }

    pub fn open(dir: impl Into<PathBuf>) -> EngineResult<Self> {
        Self::open_with(dir, Arc::new(audit::SystemClock), Box::new(crypto::OsFill))
    }

    pub fn open_with_test(
        dir: impl Into<PathBuf>,
        clock: Arc<dyn Clock + Send + Sync>,
        rng: Box<dyn FillBytes + Send>,
    ) -> EngineResult<Self> {
        Self::open_with(dir, clock, rng)
    }

    fn open_with(
        dir: impl Into<PathBuf>,
        clock: Arc<dyn Clock + Send + Sync>,
        mut rng: Box<dyn FillBytes + Send>,
    ) -> EngineResult<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        crate::fsutil::chmod_700(&dir).ok();

        let first_run = !Keychain::path(&dir).exists();
        let keychain = if first_run {
            Keychain::initialize(&dir, &mut *rng, clock.now_unix())?
        } else {
            Keychain::open(&dir)?
        };
        let audit_key = keychain.audit_key();
        audit::ensure_log_file(&Self::audit_path(&dir))?;

        let mut state: StateFile = read_if_exists(&Self::state_file_path(&dir))?.unwrap_or_else(StateFile::new);
        if state.key_generation == 0 {
            state.key_generation = keychain.current_id();
        }
        let verified = verify_chain(&Self::audit_path(&dir), &audit_key)?;
        let mut head = Self::recover_head(&dir)?;
        let _ = verified;

        // 崩溃恢复：把未完成的轮换推进到一致状态（或回滚未提升的新代次）。
        let mut keychain = keychain;
        if let Some(pending) = keychain.pending_generation() {
            Self::recover_rotation(&dir, &mut state, &mut keychain, &mut head, &audit_key, &clock, pending)?;
        }

        let engine = Engine {
            dir,
            state: Mutex::new(state),
            keychain: Mutex::new(keychain),
            head: Mutex::new(head),
            clock,
            rng: Mutex::new(rng),
            crash: Mutex::new(None),
        };

        if first_run {
            engine.audit_global("bootstrap", json!({"event": "keychain_initialized", "first_run": true}))?;
        }
        Ok(engine)
    }

    fn recover_head(dir: &Path) -> EngineResult<ChainHead> {
        let all = audit::read_all_entries(&Self::audit_path(dir))
            .map_err(|e| err_other(e.to_string()))?;
        if all.is_empty() {
            return Ok(ChainHead::genesis());
        }
        // 状态写入晚于审计：若最后若干条审计已落盘但状态未跟上，以日志实际末尾为准。
        let last = all.last().unwrap();
        let hash_vec =
            crypto::unhex(&last.entry_hash).ok_or_else(|| EngineError::Corrupt("审计摘要编码损坏".into()))?;
        let hash: [u8; 32] = hash_vec
            .try_into()
            .map_err(|_| EngineError::Corrupt("审计摘要长度错误".into()))?;
        Ok(ChainHead { seq: last.seq, hash })
    }

    fn recover_rotation(
        dir: &Path,
        state: &mut StateFile,
        keychain: &mut Keychain,
        head: &mut ChainHead,
        audit_key: &[u8],
        clock: &Arc<dyn Clock + Send + Sync>,
        pending: keys::Generation,
    ) -> EngineResult<()> {
        let new_id = pending.id;
        if keychain.is_promoted(new_id) {
            // 密钥已提升：必须向前完成，保证状态与审计指向新代次。
            state.key_generation = new_id;
            Self::persist_state_to(dir, state)?;
            let (_, nh) = append_entry(
                &Self::audit_path(dir),
                audit_key,
                *head,
                None,
                "key-rotation",
                json!({"new_generation": new_id, "recovered": true, "action": "commit"}),
                clock.as_ref(),
            )
            .map_err(|e| err_other(e.to_string()))?;
            *head = nh;
            keychain.rotate_commit(dir, new_id)?;
        } else {
            // 新代次已写入但尚未提升，且无任何数据引用：直接丢弃。
            keychain.discard_generation(dir, new_id)?;
            let (_, nh) = append_entry(
                &Self::audit_path(dir),
                audit_key,
                *head,
                None,
                "key-rotation",
                json!({"new_generation": new_id, "recovered": true, "action": "rollback"}),
                clock.as_ref(),
            )
            .map_err(|e| err_other(e.to_string()))?;
            *head = nh;
        }
        Ok(())
    }

    pub fn set_crash_point(&self, point: Option<CrashPoint>) {
        *self.crash.lock().unwrap() = point;
    }

    fn take_crash(&self, point: CrashPoint) -> EngineResult<()> {
        if *self.crash.lock().unwrap() == Some(point) {
            // 清除后返回“崩溃”，模拟进程在该点终止；持久化文件保留在崩溃瞬间状态。
            self.crash.lock().unwrap().take();
            Err(EngineError::Conflict(format!("模拟崩溃点：{point:?}")))
        } else {
            Ok(())
        }
    }

    fn persist_state_to(dir: &Path, state: &StateFile) -> EngineResult<()> {
        let bytes = serde_json::to_vec_pretty(state).unwrap();
        atomic_write(&Self::state_file_path(dir), &bytes, true)
    }

    fn audit(
        &self,
        tenant: &str,
        kind: &str,
        details: Value,
    ) -> EngineResult<()> {
        let audit_key = self.keychain.lock().unwrap().audit_key();
        let mut head = self.head.lock().unwrap();
        let (_, nh) = append_entry(
            &Self::audit_path(&self.dir),
            &audit_key,
            *head,
            Some(tenant),
            kind,
            details,
            self.clock.as_ref(),
        )
        .map_err(|e| err_other(e.to_string()))?;
        *head = nh;
        Ok(())
    }

    fn audit_global(&self, kind: &str, details: Value) -> EngineResult<()> {
        let audit_key = self.keychain.lock().unwrap().audit_key();
        let mut head = self.head.lock().unwrap();
        let (_, nh) = append_entry(
            &Self::audit_path(&self.dir),
            &audit_key,
            *head,
            None,
            kind,
            details,
            self.clock.as_ref(),
        )
        .map_err(|e| err_other(e.to_string()))?;
        *head = nh;
        Ok(())
    }

}

// ---------------- 租户与规则 ----------------

pub fn validate_tenant(tenant: &str) -> EngineResult<()> {
    if tenant.is_empty() || tenant.len() > 64 {
        return Err(EngineError::BadInput("租户标识长度需在 1..=64".into()));
    }
    if !tenant
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(EngineError::BadInput(
            "租户标识只允许字母、数字、_、-、.".into(),
        ));
    }
    Ok(())
}

fn kind_from_input(input: &RuleInput) -> EngineResult<RuleKind> {
    match input.kind.as_deref().unwrap_or("") {
        "email" => Ok(RuleKind::Email),
        "idcard" => Ok(RuleKind::IdCard),
        "regex" => {
            let pattern = input
                .pattern
                .clone()
                .ok_or_else(|| EngineError::BadInput("regex 规则需要 pattern".into()))?;
            Ok(RuleKind::Regex { pattern })
        }
        "range" => {
            let min = as_i128(input.min.as_ref())?
                .ok_or_else(|| EngineError::BadInput("range 规则需要整数 min".into()))?;
            let max = as_i128(input.max.as_ref())?
                .ok_or_else(|| EngineError::BadInput("range 规则需要整数 max".into()))?;
            Ok(RuleKind::Range { min, max })
        }
        other => Err(EngineError::BadInput(format!(
            "未知规则类型 {other:?}，可选 email/idcard/regex/range"
        ))),
    }
}

fn as_i128(v: Option<&Value>) -> EngineResult<Option<i128>> {
    match v {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(|x| Some(x as i128))
            .or_else(|| n.as_u64().map(|x| Some(x as i128)))
            .ok_or_else(|| EngineError::BadInput("范围边界必须是整数".into())),
        _ => Err(EngineError::BadInput("范围边界必须是整数".into())),
    }
}

fn view_of(rule: &Rule, version: u64) -> RuleView {
    let (kind, detail) = match &rule.kind {
        RuleKind::Email => ("email", json!({})),
        RuleKind::IdCard => ("idcard", json!({})),
        RuleKind::Regex { pattern } => ("regex", json!({"pattern": pattern})),
        RuleKind::Range { min, max } => ("range", json!({"min": min, "max": max})),
    };
    RuleView {
        id: rule.id.clone(),
        name: rule.name.clone(),
        kind: kind.into(),
        detail,
        priority: rule.priority,
        stable: rule.stable,
        enabled: rule.enabled,
        rule_version: version,
    }
}

impl Engine {
pub fn ensure_tenant(&self, tenant: &str) -> EngineResult<()> {
    validate_tenant(tenant)?;
    if self.state.lock().unwrap().tenant(tenant).is_none() {
        return Err(EngineError::NotFound(format!(
            "租户 {tenant} 尚未登记，请先创建"
        )));
    }
    Ok(())
}

pub fn create_tenant(&self, tenant: &str) -> EngineResult<()> {
    validate_tenant(tenant)?;
    let mut state = self.state.lock().unwrap();
    if state.tenant(tenant).is_some() {
        return Err(EngineError::Conflict(format!("租户 {tenant} 已存在")));
    }
    state.tenant_mut(tenant);
    Self::persist_state_to(&self.dir, &state)?;
    drop(state);
    self.audit(tenant, "tenant-create", json!({}))?;
    Ok(())
}

pub fn list_tenants(&self) -> Vec<String> {
    self.state.lock().unwrap().tenants.keys().cloned().collect()
}

pub fn list_rules(&self, tenant: &str) -> EngineResult<RuleMeta> {
    self.ensure_tenant(tenant)?;
    let state = self.state.lock().unwrap();
    let t = state.tenant(tenant).unwrap();
    Ok(RuleMeta {
        rule_version: t.rule_version,
        rules: t.rules.iter().map(|r| view_of(r, t.rule_version)).collect(),
    })
}

fn new_rule_id(rng: &mut dyn FillBytes) -> String {
    let mut b = [0u8; 8];
    rng.fill(&mut b);
    format!("rule_{}", crypto::hex(&b))
}

/// 登记新版本规则（新建或覆盖），规则集版本递增。
pub fn upsert_rule(&self, tenant: &str, input: RuleInput) -> EngineResult<RuleView> {
    self.ensure_tenant(tenant)?;
    if input.name.trim().is_empty() || input.name.len() > 100 {
        return Err(EngineError::BadInput("规则名称长度需在 1..=100".into()));
    }
    let kind = kind_from_input(&input)?;
    validate_rule(&kind)?;

    let mut state = self.state.lock().unwrap();
    let t = state.tenant_mut(tenant);
    let id = input.id.clone().unwrap_or_else(|| {
        let mut rng = self.rng.lock().unwrap();
        Self::new_rule_id(&mut **rng)
    });
    if let Some(existing) = t.rules.iter_mut().find(|r| r.id == id) {
        existing.name = input.name.clone();
        existing.kind = kind.clone();
        existing.priority = input.priority.unwrap_or(existing.priority);
        existing.stable = input.stable.unwrap_or(existing.stable);
        existing.enabled = input.enabled.unwrap_or(existing.enabled);
    } else {
        if input.id.is_some() {
            return Err(EngineError::NotFound(format!("规则 {id} 不存在")));
        }
        t.rules.push(Rule {
            id: id.clone(),
            name: input.name.clone(),
            kind: kind.clone(),
            priority: input.priority.unwrap_or(0),
            stable: input.stable.unwrap_or(true),
            enabled: input.enabled.unwrap_or(true),
        });
    }
    t.bump_version();
    let version = t.rule_version;
    Self::persist_state_to(&self.dir, &state)?;
    drop(state);

    self.audit(
        tenant,
        "rule-register",
        json!({"rule_id": id, "name": input.name, "rule_version": version}),
    )?;
    let state = self.state.lock().unwrap();
    Ok(view_of(state.tenant(tenant).unwrap().find_rule(&id).unwrap(), version))
}

pub fn delete_rule(&self, tenant: &str, rule_id: &str) -> EngineResult<u64> {
    self.ensure_tenant(tenant)?;
    let mut state = self.state.lock().unwrap();
    let t = state.tenant_mut(tenant);
    let pos = t
        .rules
        .iter()
        .position(|r| r.id == rule_id)
        .ok_or_else(|| EngineError::NotFound(format!("规则 {rule_id} 不存在")))?;
    t.rules.remove(pos);
    t.bump_version();
    let version = t.rule_version;
    Self::persist_state_to(&self.dir, &state)?;
    drop(state);
    self.audit(
        tenant,
        "rule-delete",
        json!({"rule_id": rule_id, "rule_version": version}),
    )?;
    Ok(version)
}

pub fn set_rule_enabled(
    &self,
    tenant: &str,
    rule_id: &str,
    enabled: bool,
) -> EngineResult<u64> {
    self.ensure_tenant(tenant)?;
    let mut state = self.state.lock().unwrap();
    let t = state.tenant_mut(tenant);
    let rule = t
        .rules
        .iter_mut()
        .find(|r| r.id == rule_id)
        .ok_or_else(|| EngineError::NotFound(format!("规则 {rule_id} 不存在")))?;
    rule.enabled = enabled;
    t.bump_version();
    let version = t.rule_version;
    Self::persist_state_to(&self.dir, &state)?;
    drop(state);
    self.audit(
        tenant,
        "rule-toggle",
        json!({"rule_id": rule_id, "enabled": enabled, "rule_version": version}),
    )?;
    Ok(version)
}
}

fn protected_tenant_tokens(
    tenant: &str,
    keychain: &Keychain,
    text: &str,
) -> EngineResult<Vec<(usize, usize)>> {
    let gen_ids = keychain.generation_ids();
    let mut protected = Vec::new();
    for (s, e, parsed) in tokens::scan(text) {
        let ok = tokens::verify_for_tenant(&parsed, tenant, &gen_ids, &|gen| {
            keychain.token_tag_key(gen, tenant).ok()
        })
        .is_some();
        if ok {
            protected.push((s, e));
        }
    }
    Ok(protected)
}

fn collect_hits(tenant_state: &TenantState, text: &str) -> EngineResult<Vec<Hit>> {
    let mut hits = Vec::new();
    for rule in &tenant_state.rules {
        hits.extend(model::find_hits(rule, text)?);
    }
    Ok(hits)
}

fn make_token(
    keychain: &Keychain,
    gen: u64,
    tenant: &str,
    id: &[u8],
) -> EngineResult<String> {
    let tag_key = keychain.token_tag_key(gen, tenant)?;
    let tag = tokens::token_tag(&tag_key, gen, tenant, id);
    Ok(tokens::build(gen, id, &tag))
}

/// 单条命中对应的记录 ID：稳定规则按 (代次,版本,原文) 派生；随机规则取随机数。
fn resolve_record_id(
    keychain: &Keychain,
    tenant: &str,
    rule_version: u64,
    stable: bool,
    original: &str,
    existing: &BTreeMap<String, MappingRecord>,
    rng: &mut dyn FillBytes,
) -> EngineResult<(String, Vec<u8>)> {
    let gen = keychain.current_id();
    if stable {
        let id_key = keychain.stable_id_key(gen, tenant)?;
        let id = tokens::stable_record_id(&id_key, rule_version, original);
        let id_b64 = b64::encode(&id);
        return Ok((id_b64, id));
    }
    // 随机 token：避免极小概率 ID 碰撞。
    loop {
        let mut id = vec![0u8; 16];
        rng.fill(&mut id);
        let id_b64 = b64::encode(&id);
        if !existing.contains_key(&id_b64) {
            return Ok((id_b64, id));
        }
    }
}


impl Engine {
    /// 预览：执行规则识别与重叠裁决，但不落库、不加密；token 为“建议形态”。
    pub fn preview(&self, tenant: &str, text: &str) -> EngineResult<RedactionOutput> {
        self.ensure_tenant(tenant)?;
        let keychain = self.keychain.lock().unwrap();
        let state = self.state.lock().unwrap();
        let t = state.tenant(tenant).unwrap();
        let protected = protected_tenant_tokens(tenant, &keychain, text)?;
        let hits = collect_hits(t, text)?;
        let adj = adjudicate(hits, &protected);
        let gen = keychain.current_id();
        let mut token_map: BTreeMap<(usize, usize), String> = BTreeMap::new();
        let mut accepted = Vec::new();
        for h in &adj.accepted {
            let token = if h.stable {
                let id_key = keychain.stable_id_key(gen, tenant)?;
                let id = tokens::stable_record_id(&id_key, t.rule_version, &h.text);
                let tag_key = keychain.token_tag_key(gen, tenant)?;
                let tag = tokens::token_tag(&tag_key, gen, tenant, &id);
                tokens::build(gen, &id, &tag)
            } else {
                format!("MTKN-G{gen}-<random-on-apply>")
            };
            token_map.insert((h.start, h.end), token.clone());
            accepted.push(HitView {
                rule_id: h.rule_id.clone(),
                rule_name: h.rule_name.clone(),
                start: h.start,
                end: h.end,
                text: h.text.clone(),
                priority: h.priority,
                stable: h.stable,
                token: Some(token),
            });
        }
        let replaced = apply_replacement(text, &adj.accepted, &|s, e| {
            token_map.get(&(s, e)).cloned().unwrap_or_else(|| "MTKN-PREVIEW".into())
        });
        Ok(RedactionOutput {
            text: replaced,
            rule_version: t.rule_version,
            key_generation: gen,
            accepted,
            suppressed: adj.suppressed.into_iter().map(into_suppressed).collect(),
            token_protected: protected.len(),
        })
    }

    /// 执行脱敏：生成 token、加密保存映射并落库；再次处理保持不变（幂等）。
    pub fn redact(&self, tenant: &str, text: &str) -> EngineResult<RedactionOutput> {
        self.ensure_tenant(tenant)?;
        let keychain = self.keychain.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        let t = state.tenant_mut(tenant);
        let rule_version = t.rule_version;
        let protected = protected_tenant_tokens(tenant, &keychain, text)?;
        let hits = collect_hits(t, text)?;
        let adj = adjudicate(hits, &protected);
        let gen = keychain.current_id();
        let data_key = keychain.data_key(gen, tenant)?;
        let now = self.clock.now_unix();

        let mut token_by_span: BTreeMap<(usize, usize), String> = BTreeMap::new();
        let mut new_records: Vec<MappingRecord> = Vec::new();
        let existing: BTreeMap<String, MappingRecord> = t.mappings.clone();

        for h in &adj.accepted {
            let mut rng = self.rng.lock().unwrap();
            let (id_b64, id) =
                resolve_record_id(&keychain, tenant, rule_version, h.stable, &h.text, &existing, &mut **rng)?;
            drop(rng);
            let token = make_token(&keychain, gen, tenant, &id)?;

            // 稳定映射可能此前已写入（同代次、同版本、同原文），直接复用。
            if !t.mappings.contains_key(&id_b64) {
                let mut nonce = vec![0u8; 12];
                self.rng.lock().unwrap().fill(&mut nonce);
                let aad = keys::mapping_aad(gen, tenant, &id_b64);
                let ct = seal(&data_key, &nonce, &aad, h.text.as_bytes());
                new_records.push(MappingRecord {
                    id_b64: id_b64.clone(),
                    gen,
                    original_cipher_hex: crypto::hex(&ct),
                    nonce_hex: crypto::hex(&nonce),
                    rule_id: h.rule_id.clone(),
                    stable: h.stable,
                    created_unix: now,
                });
            }
            token_by_span.insert((h.start, h.end), token);
        }

        let replaced = apply_replacement(text, &adj.accepted, &|s, e| {
            token_by_span
                .get(&(s, e))
                .cloned()
                .unwrap_or_else(|| "MTKN-ERR".into())
        });

        for rec in new_records {
            t.mappings.insert(rec.id_b64.clone(), rec);
        }
        t.redactions.push(RedactionRecord {
            unix: now,
            rule_version,
            text: replaced.clone(),
            accepted: adj.accepted.len(),
            suppressed: adj.suppressed.len(),
        });

        let accepted_views: Vec<HitView> = adj
            .accepted
            .iter()
            .map(|h| HitView {
                rule_id: h.rule_id.clone(),
                rule_name: h.rule_name.clone(),
                start: h.start,
                end: h.end,
                text: h.text.clone(),
                priority: h.priority,
                stable: h.stable,
                token: token_by_span.get(&(h.start, h.end)).cloned(),
            })
            .collect();
        let suppressed_views: Vec<SuppressedView> = adj.suppressed.iter().cloned().map(into_suppressed).collect();
        let protected_count = protected.len();

        // 先持久化加密状态，再写审计（若随后崩溃，恢复时审计向前补齐不影响一致性）。
        Self::persist_state_to(&self.dir, &state)?;
        drop(state);
        drop(keychain);

        self.audit(
            tenant,
            "redact",
            json!({
                "rule_version": rule_version,
                "key_generation": gen,
                "accepted": accepted_views.len(),
                "suppressed": suppressed_views.len(),
                "existing_tokens_protected": protected_count,
                "length": replaced.len(),
            }),
        )?;

        Ok(RedactionOutput {
            text: replaced,
            rule_version,
            key_generation: gen,
            accepted: accepted_views,
            suppressed: suppressed_views,
            token_protected: protected_count,
        })
    }

    /// 内部：校验 token 并取出映射记录（不审计）。
    fn resolve_token(
        &self,
        tenant: &str,
        token: &str,
    ) -> EngineResult<(ParsedToken, Vec<u8>, MappingRecord, Vec<u8>)> {
        let parsed = tokens::parse(token).ok_or(EngineError::InvalidToken)?;
        let keychain = self.keychain.lock().unwrap();
        let gen_ids = keychain.generation_ids();
        let verified =
            tokens::verify_for_tenant(&parsed, tenant, &gen_ids, &|g| {
                keychain.token_tag_key(g, tenant).ok()
            })
            .ok_or(EngineError::InvalidToken)?;
        let (id_b64, id) = verified;
        let state = self.state.lock().unwrap();
        let t = state.tenant(tenant).ok_or(EngineError::InvalidToken)?;
        let record = t
            .mappings
            .get(&id_b64)
            .cloned()
            .ok_or(EngineError::InvalidToken)?;
        if record.gen != parsed.gen {
            // 标签代次与映射写入代次不一致：拒绝（不给出差异细节）。
            return Err(EngineError::InvalidToken);
        }
        let data_key = keychain.data_key(record.gen, tenant)?;
        Ok((parsed, id, record, data_key))
    }

    /// 单个还原：仅接受 token + 用途说明。
    pub fn restore(&self, tenant: &str, token: &str, purpose: &str) -> EngineResult<String> {
        self.ensure_tenant(tenant)?;
        if purpose.trim().is_empty() || purpose.len() > 500 {
            return Err(EngineError::BadInput("用途说明必填且不超过 500 字".into()));
        }
        match self.try_decrypt(tenant, token) {
            Ok(original) => {
                self.audit(
                    tenant,
                    "restore-ok",
                    json!({"purpose": purpose, "token_fingerprint": fingerprint(token), "result": "ok"}),
                )?;
                Ok(original)
            }
            Err(e) => {
                self.audit(
                    tenant,
                    "restore-denied",
                    json!({"purpose": purpose, "token_fingerprint": fingerprint(token), "result": "denied"}),
                )?;
                Err(e)
            }
        }
    }

    fn try_decrypt(&self, tenant: &str, token: &str) -> EngineResult<String> {
        let (_, _id, record, data_key) = self.resolve_token(tenant, token)?;
        let nonce = crypto::unhex(&record.nonce_hex)
            .ok_or(EngineError::InvalidToken)?;
        let ct = crypto::unhex(&record.original_cipher_hex)
            .ok_or(EngineError::InvalidToken)?;
        let aad = keys::mapping_aad(record.gen, tenant, &record.id_b64);
        // aes-gcm 解密：复用 open 校验，明文需单独取回。
        let plaintext =
            decrypt_mapping(&data_key, &nonce, &aad, &ct).ok_or(EngineError::InvalidToken)?;
        String::from_utf8(plaintext).map_err(|_| EngineError::InvalidToken)
    }

    /// 批量还原：单项失败不影响其他项；失败信息统一，不暴露是否属于别的租户。
    pub fn restore_batch(
        &self,
        tenant: &str,
        items: Vec<(String, String)>,
    ) -> EngineResult<Vec<RestoreItemOutput>> {
        self.ensure_tenant(tenant)?;
        for (_, purpose) in &items {
            if purpose.trim().is_empty() || purpose.len() > 500 {
                return Err(EngineError::BadInput("每项用途说明必填且不超过 500 字".into()));
            }
        }
        let mut out = Vec::with_capacity(items.len());
        for (index, (token, purpose)) in items.into_iter().enumerate() {
            match self.try_decrypt(tenant, &token) {
                Ok(original) => {
                    self.audit(
                        tenant,
                        "restore-ok",
                        json!({"purpose": purpose, "token_fingerprint": fingerprint(&token), "result": "ok", "batch_index": index}),
                    )?;
                    out.push(RestoreItemOutput {
                        index,
                        ok: true,
                        original: Some(original),
                        error: None,
                    });
                }
                Err(_) => {
                    self.audit(
                        tenant,
                        "restore-denied",
                        json!({"purpose": purpose, "token_fingerprint": fingerprint(&token), "result": "denied", "batch_index": index}),
                    )?;
                    out.push(RestoreItemOutput {
                        index,
                        ok: false,
                        original: None,
                        error: Some(EngineError::InvalidToken.message()),
                    });
                }
            }
        }
        Ok(out)
    }
}

fn decrypt_mapping(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
}

fn fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    crypto::hex(&Sha256::digest(token.as_bytes()))[..16].to_string()
}

fn into_suppressed(s: model::Suppressed) -> SuppressedView {
    SuppressedView {
        rule_id: s.rule_id,
        rule_name: s.rule_name,
        start: s.start,
        end: s.end,
        text: s.text,
        reason: s.reason,
        by_rule_id: s.by_rule_id,
    }
}

/// 从右向左替换，保证字节偏移始终有效。
fn apply_replacement(text: &str, accepted: &[model::Hit], token_for: &dyn Fn(usize, usize) -> String) -> String {
    let mut spans: Vec<&model::Hit> = accepted.iter().collect();
    spans.sort_by(|a, b| b.start.cmp(&a.start));
    let mut out = text.to_string();
    for h in spans {
        let token = token_for(h.start, h.end);
        out.replace_range(h.start..h.end, &token);
    }
    out
}

// ---------------- 密钥轮换、审计查看、导出 ----------------

impl Engine {
    pub fn key_info(&self) -> Value {
        let kc = self.keychain.lock().unwrap();
        let state = self.state.lock().unwrap();
        json!({
            "current_generation": kc.current_id(),
            "write_generation": state.key_generation,
            "retained_generations": kc.generation_ids(),
            "pending": kc.pending_generation().map(|g| g.id),
        })
    }

    /// 密钥轮换：写入新代次 → 提升 → 状态指向新代次 → 审计确认并提交。
    /// 任一步“掉电”后，重开引擎都会恢复到一致状态（前向完成或回滚未用新代次）。
    pub fn rotate_key(&self) -> EngineResult<Value> {
        let now = self.clock.now_unix();
        let new_id = {
            let mut kc = self.keychain.lock().unwrap();
            let mut rng = self.rng.lock().unwrap();
            kc.rotate_write_new(&self.dir, &mut **rng, now)?
        };
        // 崩溃点 1：新密钥已落盘，但当前代次与状态仍是旧的 → 重启回滚。
        self.take_crash(CrashPoint::AfterKeyWritten)?;

        {
            let mut kc = self.keychain.lock().unwrap();
            kc.rotate_promote(&self.dir, new_id)?;
        }
        // 崩溃点 2：当前代次已提升，但状态/审计尚未指向新代次 → 重启前向完成。
        self.take_crash(CrashPoint::AfterPromoted)?;

        {
            let mut state = self.state.lock().unwrap();
            state.key_generation = new_id;
            Self::persist_state_to(&self.dir, &state)?;
        }
        // 崩溃点 3：状态已指向新代次，但提交标记/审计未落盘 → 重启前向完成。
        self.take_crash(CrashPoint::AfterState)?;

        self.audit_global(
            "key-rotation",
            json!({"new_generation": new_id, "recovered": false, "action": "commit"}),
        )?;
        {
            let mut kc = self.keychain.lock().unwrap();
            kc.rotate_commit(&self.dir, new_id)?;
        }
        Ok(self.key_info())
    }

    pub fn read_audit(&self, tenant: Option<&str>, limit: Option<usize>) -> EngineResult<Vec<AuditEntry>> {
        let all = audit::read_all_entries(&Self::audit_path(&self.dir))
            .map_err(|e| err_other(e.to_string()))?;
        let filtered: Vec<AuditEntry> = all
            .into_iter()
            .filter(|e| match tenant {
                Some(t) => e.tenant.as_deref() == Some(t),
                None => true,
            })
            .collect();
        let limit = limit.unwrap_or(200).min(10_000);
        Ok(filtered.into_iter().rev().take(limit).collect())
    }

    pub fn verify_audit(&self) -> EngineResult<AuditSummary> {
        let audit_key = self.keychain.lock().unwrap().audit_key();
        let report: VerifyReport =
            verify_chain(&Self::audit_path(&self.dir), &audit_key).map_err(|e| err_other(e.to_string()))?;
        let head = self.head.lock().unwrap();
        Ok(AuditSummary {
            entries: report.entries,
            last_seq: head.seq,
            last_hash: head.hex(),
            ok: report.ok,
            error: report.error,
        })
    }

    /// 导出：只含已脱敏文本、规则元数据与审计摘要，绝不包含原文映射或密文。
    pub fn export(&self) -> EngineResult<ExportBundle> {
        let state = self.state.lock().unwrap();
        let audit_summary = self.verify_audit()?;
        let mut tenants = BTreeMap::new();
        for (id, t) in &state.tenants {
            tenants.insert(
                id.clone(),
                TenantExport {
                    rule_metadata: RuleMeta {
                        rule_version: t.rule_version,
                        rules: t.rules.iter().map(|r| view_of(r, t.rule_version)).collect(),
                    },
                    redactions: t.redactions.clone(),
                },
            );
        }
        Ok(ExportBundle {
            exported_unix: self.clock.now_unix(),
            tenants,
            audit_summary,
        })
    }

    /// 审计日志路径（测试篡改用）。
    pub fn audit_log_path(&self) -> PathBuf {
        Self::audit_path(&self.dir)
    }

    pub fn state_path(&self) -> PathBuf {
        Self::state_file_path(&self.dir)
    }

    /// 仅供测试：直接查看某租户映射使用的代次集合（不暴露密文内容）。
    pub fn mapping_generations_for_test(&self, tenant: &str) -> EngineResult<BTreeSet<u64>> {
        let state = self.state.lock().unwrap();
        let t = state.tenant(tenant).ok_or_else(|| EngineError::NotFound("租户不存在".into()))?;
        Ok(t.mappings.values().map(|m| m.gen).collect())
    }

    pub fn mapping_count_for_test(&self, tenant: &str) -> EngineResult<usize> {
        let state = self.state.lock().unwrap();
        Ok(state.tenant(tenant).map(|t| t.mappings.len()).unwrap_or(0))
    }

    pub fn current_write_generation(&self) -> u64 {
        self.state.lock().unwrap().key_generation
    }
}

/// 供审计/其他模块读取枚举值（避免未使用告警）。
fn _use_phase(p: RotationPhase) -> &'static str {
    match p {
        RotationPhase::KeyWritten => "key_written",
        RotationPhase::Committed => "committed",
    }
}

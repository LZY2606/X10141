use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{self, KeyFile};
use crate::engine;
use crate::state::{AuditRecord, MappingRecord, RedactionEntry, Rule, State, Store};

/// 统一错误：不区分“不存在 / 格式错误 / 属于其他租户”，避免泄露归属。
pub const RESTORE_ERROR: &str = "无法还原：token 无效或未被授权";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn audit_hash(seq: u64, ts: u64, kind: &str, detail: &Value, prev_hash: &str) -> String {
    let payload = json!({
        "seq": seq,
        "ts": ts,
        "kind": kind,
        "detail": detail,
        "prev_hash": prev_hash,
    });
    let mut hasher = Sha256::new();
    hasher.update(payload.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

fn push_audit(state: &mut State, kind: &str, detail: Value) {
    let seq = state.audit.len() as u64;
    let prev_hash = state.audit.last().map(|a| a.hash.clone()).unwrap_or_else(|| "0".repeat(64));
    let ts = now_ms();
    let hash = audit_hash(seq, ts, kind, &detail, &prev_hash);
    state.audit.push(AuditRecord { seq, ts, kind: kind.to_string(), detail, prev_hash, hash });
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanRef {
    pub rule_id: String,
    pub version: u32,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanInfo {
    pub rule_id: String,
    pub version: u32,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuppressedInfo {
    pub rule_id: String,
    pub version: u32,
    pub start: usize,
    pub end: usize,
    pub matched: String,
    pub suppressed_by: SpanRef,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub accepted: Vec<SpanInfo>,
    pub suppressed: Vec<SuppressedInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenInfo {
    pub token: String,
    pub token_id: String,
    pub rule_id: String,
    pub version: u32,
    pub matched: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RedactOutcome {
    pub redacted: String,
    pub tokens: Vec<TokenInfo>,
    pub suppressed: Vec<SuppressedInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestoreItem {
    pub token: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditSummary {
    pub length: usize,
    pub head: Option<String>,
    pub hashes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Export {
    pub rules: Vec<Rule>,
    pub current_gen: u32,
    pub redacted_texts: Vec<RedactionEntry>,
    pub audit: AuditSummary,
}

pub struct Vault {
    pub store: Store,
}

impl Vault {
    /// 真实启动：首次生成本地随机密钥，否则加载已有仓库。
    pub fn open_or_init(dir: &Path) -> io::Result<Vault> {
        if Store::exists(dir) {
            Ok(Vault { store: Store::open(dir)? })
        } else {
            Ok(Vault { store: Store::init(dir, KeyFile::generate())? })
        }
    }

    pub fn load(dir: &Path) -> io::Result<Vault> {
        Ok(Vault { store: Store::open(dir)? })
    }

    /// 测试用：以确定密钥初始化。
    pub fn init_with_keys(dir: &Path, master: [u8; 32], gen: [u8; 32]) -> io::Result<Vault> {
        Ok(Vault { store: Store::init(dir, KeyFile::deterministic(master, gen))? })
    }

    fn adjudicate(&self, text: &str) -> engine::Adjudication {
        let rules = &self.store.state.rules;
        let protected = engine::protected_spans(text);
        let candidates = engine::find_candidates(rules, text);
        engine::adjudicate(rules, candidates, &protected)
    }

    fn suppressed_infos(&self, adj: &engine::Adjudication) -> Vec<SuppressedInfo> {
        let rules = &self.store.state.rules;
        adj.suppressed
            .iter()
            .map(|s| {
                let cr = &rules[s.cand.rule_idx];
                let br = &rules[s.by.rule_idx];
                SuppressedInfo {
                    rule_id: cr.id.clone(),
                    version: cr.version,
                    start: s.cand.start,
                    end: s.cand.end,
                    matched: s.cand.matched.clone(),
                    suppressed_by: SpanRef { rule_id: br.id.clone(), version: br.version, start: s.by.start, end: s.by.end },
                }
            })
            .collect()
    }

    pub fn register_rule(&mut self, rule: Rule) -> Result<(), String> {
        if rule.id.is_empty() || rule.pattern.is_empty() {
            return Err("规则 id 与 pattern 不能为空".to_string());
        }
        if rule.kind == crate::state::MatchKind::Regex {
            regex::Regex::new(&rule.pattern).map_err(|e| format!("正则无效: {e}"))?;
        }
        let state = &mut self.store.state;
        state.rules.retain(|r| r.id != rule.id);
        push_audit(
            state,
            "rule_register",
            json!({"rule_id": rule.id, "version": rule.version, "kind": format!("{:?}", rule.kind), "priority": rule.priority, "stable": rule.stable}),
        );
        state.rules.push(rule);
        state.rules.sort_by(|a, b| a.id.cmp(&b.id));
        self.store.save_state().map_err(|e| e.to_string())
    }

    pub fn preview(&self, text: &str) -> Preview {
        let adj = self.adjudicate(text);
        let rules = &self.store.state.rules;
        let accepted = adj
            .accepted
            .iter()
            .map(|c| {
                let r = &rules[c.rule_idx];
                SpanInfo { rule_id: r.id.clone(), version: r.version, start: c.start, end: c.end, matched: c.matched.clone() }
            })
            .collect();
        Preview { accepted, suppressed: self.suppressed_infos(&adj) }
    }

    pub fn redact(&mut self, tenant: &str, text: &str) -> Result<RedactOutcome, String> {
        if tenant.is_empty() {
            return Err("租户不能为空".to_string());
        }
        let rules = self.store.state.rules.clone();
        let adj = self.adjudicate(text);
        let suppressed = self.suppressed_infos(&adj);
        let master = self.store.keys.master();
        let current_gen = self.store.state.current_gen;
        let gen_key = self.store.keys.key_for(current_gen).ok_or_else(|| "当前密钥代次不存在".to_string())?;

        let mut redacted = text.to_string();
        let mut tokens: Vec<TokenInfo> = Vec::new();
        for cand in adj.accepted.iter().rev() {
            let rule = &rules[cand.rule_idx];
            let salt = if rule.stable {
                None
            } else {
                let mut s = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
                Some(s)
            };
            let tid = crypto::token_id(&master, tenant, &rule.id, rule.version, &cand.matched, salt.as_ref().map(|s| &s[..]));
            if !self.store.state.mappings.contains_key(&tid) {
                let payload = json!({
                    "tenant": tenant,
                    "rule_id": rule.id,
                    "version": rule.version,
                    "plaintext": cand.matched,
                });
                let (nonce_b64, ciphertext_b64) = crypto::encrypt(&gen_key, &tid, payload.to_string().as_bytes());
                self.store.state.mappings.insert(
                    tid.clone(),
                    MappingRecord { token_id: tid.clone(), gen: current_gen, nonce_b64, ciphertext_b64, created_ms: now_ms() },
                );
            }
            let token = engine::make_token(&tid);
            redacted.replace_range(cand.start..cand.end, &token);
            tokens.push(TokenInfo { token, token_id: tid, rule_id: rule.id.clone(), version: rule.version, matched: cand.matched.clone() });
        }
        tokens.reverse();

        self.store.state.redactions.push(RedactionEntry {
            tenant: tenant.to_string(),
            redacted_text: redacted.clone(),
            token_ids: tokens.iter().map(|t| t.token_id.clone()).collect(),
            ts: now_ms(),
        });
        push_audit(
            &mut self.store.state,
            "redact",
            json!({
                "tenant": tenant,
                "count": tokens.len(),
                "tokens": tokens.iter().map(|t| json!({"token_id": t.token_id, "rule_id": t.rule_id, "version": t.version})).collect::<Vec<_>>(),
            }),
        );
        self.store.save_state().map_err(|e| e.to_string())?;
        Ok(RedactOutcome { redacted, tokens, suppressed })
    }

    /// 批量还原：逐项独立，无效项不影响其他项；所有失败返回统一错误。
    pub fn restore(&mut self, purpose: &str, tokens: &[String]) -> Vec<RestoreItem> {
        if purpose.trim().is_empty() {
            return tokens
                .iter()
                .map(|t| RestoreItem { token: t.clone(), ok: false, text: None, error: Some("必须填写用途说明".to_string()) })
                .collect();
        }
        let mut results = Vec::new();
        for input in tokens {
            let plaintext = engine::extract_token_id(input)
                .and_then(|tid| self.store.state.mappings.get(&tid).cloned().map(|m| (tid, m)))
                .and_then(|(tid, m)| {
                    self.store
                        .keys
                        .key_for(m.gen)
                        .and_then(|k| crypto::decrypt(&k, &tid, &m.nonce_b64, &m.ciphertext_b64).ok())
                })
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|v| v.get("plaintext").and_then(|p| p.as_str()).map(|s| s.to_string()));

            match plaintext {
                Some(text) => {
                    push_audit(&mut self.store.state, "restore_ok", json!({"token": input, "purpose": purpose}));
                    results.push(RestoreItem { token: input.clone(), ok: true, text: Some(text), error: None });
                }
                None => {
                    push_audit(&mut self.store.state, "restore_fail", json!({"token": input, "purpose": purpose}));
                    results.push(RestoreItem { token: input.clone(), ok: false, text: None, error: Some(RESTORE_ERROR.to_string()) });
                }
            }
        }
        let _ = self.store.save_state();
        results
    }

    /// 轮换：第一步原子写入新代次密钥，第二步原子更新 current_gen + 审计。
    /// 两步之间崩溃 => keys.json 多一个未启用代次，状态与审计仍指向旧代次，保持一致。
    pub fn rotate(&mut self) -> io::Result<u32> {
        let new_id = self.store.keys.add_generation();
        self.store.save_keys()?;
        let old = self.store.state.current_gen;
        self.store.state.current_gen = new_id;
        push_audit(&mut self.store.state, "rotate", json!({"from": old, "to": new_id}));
        self.store.save_state()?;
        Ok(new_id)
    }

    pub fn verify_audit(&self) -> bool {
        let mut prev = "0".repeat(64);
        for (i, rec) in self.store.state.audit.iter().enumerate() {
            if rec.seq != i as u64 || rec.prev_hash != prev {
                return false;
            }
            if audit_hash(rec.seq, rec.ts, &rec.kind, &rec.detail, &rec.prev_hash) != rec.hash {
                return false;
            }
            prev = rec.hash.clone();
        }
        true
    }

    /// 导出：仅脱敏文本、规则元数据与审计摘要，不含任何原文映射。
    pub fn export(&self) -> Export {
        let state = &self.store.state;
        Export {
            rules: state.rules.clone(),
            current_gen: state.current_gen,
            redacted_texts: state.redactions.clone(),
            audit: AuditSummary {
                length: state.audit.len(),
                head: state.audit.last().map(|a| a.hash.clone()),
                hashes: state.audit.iter().map(|a| a.hash.clone()).collect(),
            },
        }
    }
}

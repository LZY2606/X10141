//! 追加式链式审计：每条记录包含前一条摘要与 HMAC 标签，防无痕改写。

use crate::crypto::{cat, hex, hmac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct ChainHead {
    pub seq: u64,
    pub hash: [u8; 32],
}

impl ChainHead {
    pub fn genesis() -> Self {
        let h = Sha256::digest(b"maskroom-audit-genesis-v1");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&h);
        Self { seq: 0, hash }
    }
    pub fn hex(&self) -> String {
        hex(&self.hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts_unix: i64,
    /// 全局事件（如轮换）为 None。
    pub tenant: Option<String>,
    pub kind: String,
    pub details: Value,
    pub prev_hash: String,
    pub entry_hash: String,
    pub tag: String,
}

pub trait Clock {
    fn now_unix(&self) -> i64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// 测试用固定/步进时钟。
pub struct FixedClock {
    pub value: std::sync::Mutex<i64>,
}
impl FixedClock {
    pub fn new(start: i64) -> Self {
        Self { value: std::sync::Mutex::new(start) }
    }
    pub fn tick(&self, by: i64) {
        *self.value.lock().unwrap() += by;
    }
}
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        *self.value.lock().unwrap()
    }
}

/// 递归生成键排序的规范化 JSON（数字不重排、数组保序、字符串转义）。
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn entry_input(
    seq: u64,
    ts: i64,
    tenant: &Option<String>,
    kind: &str,
    details: &Value,
    prev_hex: &str,
) -> Vec<u8> {
    let tenant_bytes = tenant.as_deref().unwrap_or("").as_bytes();
    cat(&[
        b"maskroom-audit-v1",
        &seq.to_be_bytes(),
        &ts.to_be_bytes(),
        tenant_bytes,
        kind.as_bytes(),
        canonical_json(details).as_bytes(),
        prev_hex.as_bytes(),
    ])
}

pub fn hash_entry(
    seq: u64,
    ts: i64,
    tenant: &Option<String>,
    kind: &str,
    details: &Value,
    prev_hex: &str,
) -> [u8; 32] {
    let input = entry_input(seq, ts, tenant, kind, details, prev_hex);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(input));
    out
}

pub fn tag_entry(audit_key: &[u8], entry_hash: &[u8]) -> String {
    hex(&hmac(audit_key, &[b"maskroom-audit-tag-v1", entry_hash]))
}

/// 追加一条审计到日志文件（O_APPEND 直接落盘 + flush，保持严格追加）。
pub fn append_entry(
    log_path: &Path,
    audit_key: &[u8],
    head: ChainHead,
    tenant: Option<&str>,
    kind: &str,
    details: Value,
    clock: &dyn Clock,
) -> std::io::Result<(AuditEntry, ChainHead)> {
    let seq = head.seq + 1;
    let ts = clock.now_unix();
    let tenant = tenant.map(|s| s.to_string());
    let prev_hex = head.hex();
    let hash = hash_entry(seq, ts, &tenant, kind, &details, &prev_hex);
    let hash_hex = hex(&hash);
    let tag = tag_entry(audit_key, &hash);
    let entry = AuditEntry {
        seq,
        ts_unix: ts,
        tenant,
        kind: kind.to_string(),
        details,
        prev_hash: prev_hex,
        entry_hash: hash_hex,
        tag,
    };
    let mut line = serde_json::to_string(&entry).expect("审计可序列化");
    line.push('\n');

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(log_path)?;
    f.write_all(line.as_bytes())?;
    f.flush()?;
    let new_head = ChainHead { seq, hash };
    Ok((entry, new_head))
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub entries: u64,
    pub ok: bool,
    pub error: Option<String>,
}

fn read_entries(path: &Path) -> std::io::Result<(Vec<AuditEntry>, Vec<String>)> {
    let mut entries = Vec::new();
    let mut bad_lines = Vec::new();
    if !path.exists() {
        return Ok((entries, bad_lines));
    }
    let content = std::fs::read_to_string(path)?;
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(e) => entries.push(e),
            Err(_) => bad_lines.push(format!("第 {} 行无法解析", idx + 1)),
        }
    }
    Ok((entries, bad_lines))
}

/// 逐条重算链式摘要与 HMAC；任何插入/删除/改写都会被发现。
pub fn verify_chain(log_path: &Path, audit_key: &[u8]) -> std::io::Result<VerifyReport> {
    let (entries, bad_lines) = read_entries(log_path)?;
    if let Some(msg) = bad_lines.first() {
        return Ok(VerifyReport {
            entries: entries.len() as u64,
            ok: false,
            error: Some(msg.clone()),
        });
    }
    let mut head = ChainHead::genesis();
    for e in &entries {
        if e.seq != head.seq + 1 {
            return Ok(VerifyReport {
                entries: entries.len() as u64,
                ok: false,
                error: Some(format!("第 {} 条序号断链", head.seq + 1)),
            });
        }
        if e.prev_hash != head.hex() {
            return Ok(VerifyReport {
                entries: entries.len() as u64,
                ok: false,
                error: Some(format!("第 {} 条 prev_hash 不匹配（可能被删除或插入）", e.seq)),
            });
        }
        let hash = hash_entry(e.seq, e.ts_unix, &e.tenant, &e.kind, &e.details, &e.prev_hash);
        if hex(&hash) != e.entry_hash {
            return Ok(VerifyReport {
                entries: entries.len() as u64,
                ok: false,
                error: Some(format!("第 {} 条内容摘要不匹配（正文被改写）", e.seq)),
            });
        }
        let expected_tag = tag_entry(audit_key, &hash);
        if expected_tag != e.tag {
            return Ok(VerifyReport {
                entries: entries.len() as u64,
                ok: false,
                error: Some(format!("第 {} 条标签无效（密钥不匹配或标签被伪造）", e.seq)),
            });
        }
        head = ChainHead { seq: e.seq, hash };
    }
    Ok(VerifyReport { entries: entries.len() as u64, ok: true, error: None })
}

pub fn read_all_entries(log_path: &Path) -> std::io::Result<Vec<AuditEntry>> {
    Ok(read_entries(log_path)?.0)
}

/// 确保日志文件存在且权限受限（POSIX 0600）。
pub fn ensure_log_file(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        File::create(path)?;
    }
    crate::fsutil::chmod_600(path)?;
    Ok(())
}

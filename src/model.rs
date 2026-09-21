use serde::{Deserialize, Serialize};

/// 一条脱敏规则。同名规则重复登记会产生新版本，旧版本保留，
/// 以便既有 token 的推导上下文（租户 + 规则名 + 版本 + 原文）保持可解释。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u64,
    pub tenant: String,
    pub name: String,
    pub version: u64,
    pub pattern: String,
    pub priority: i64,
    /// true: 同租户 + 同规则版本 + 同原文 => 稳定 token；false: 每次随机。
    pub stable: bool,
    pub enabled: bool,
    pub created_seq: u64,
}

/// 一篇已脱敏文档。只保存脱敏后的文本，绝不保存原文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: u64,
    pub tenant: String,
    pub redacted_text: String,
    pub token_count: usize,
    pub created_seq: u64,
}

/// 原文 <-> token 映射（内存中的明文形态；落盘时整体加密）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub token: String,
    pub tenant: String,
    pub rule_name: String,
    pub rule_version: u64,
    pub original: String,
    pub created_seq: u64,
}

/// 映射的落盘形态：AES-256-GCM 密文 + 密钥代次。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRecord {
    pub gen: u64,
    pub nonce: String,
    pub ct: String,
}

/// 链式审计条目：hash = SHA256(规范序列化(除 hash 外的全部字段))。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub tenant: String,
    pub gen: u64,
    pub payload: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    pub fn compute_hash(
        seq: u64,
        ts: u64,
        kind: &str,
        tenant: &str,
        gen: u64,
        payload: &serde_json::Value,
        prev_hash: &str,
    ) -> String {
        // serde_json 的 Map 默认按键排序，序列化结果稳定，可跨重启复算。
        let preimage = serde_json::to_string(&serde_json::json!({
            "seq": seq,
            "ts": ts,
            "kind": kind,
            "tenant": tenant,
            "gen": gen,
            "payload": payload,
            "prev_hash": prev_hash,
        }))
        .expect("审计字段可序列化");
        crate::crypto::hex_encode(&crate::crypto::sha256(preimage.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub active_gen: u64,
    pub next_rule_id: u64,
    pub next_doc_id: u64,
    pub seq: u64,
    pub rules: Vec<Rule>,
    pub documents: Vec<Document>,
}

impl Default for State {
    fn default() -> Self {
        State {
            active_gen: 1,
            next_rule_id: 1,
            next_doc_id: 1,
            seq: 0,
            rules: Vec::new(),
            documents: Vec::new(),
        }
    }
}

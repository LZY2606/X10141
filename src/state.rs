//! 持久化状态：租户规则（带版本）、加密映射、脱敏输出留存（仅含已脱敏文本）。

use crate::model::Rule;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRecord {
    pub id_b64: String,
    /// 该映射写入时的密钥代次（解密时必须找到同代次旧密钥）。
    pub gen: u64,
    pub original_cipher_hex: String,
    pub nonce_hex: String,
    pub rule_id: String,
    pub stable: bool,
    pub created_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRecord {
    pub unix: i64,
    pub rule_version: u64,
    pub text: String,
    pub accepted: usize,
    pub suppressed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantState {
    /// 每次规则集变更（登记/修改/删除/启停）递增；稳定 token 绑定此版本。
    pub rule_version: u64,
    pub rules: Vec<Rule>,
    /// key = record id 的 b64。只存放密文，绝不出现明文。
    pub mappings: BTreeMap<String, MappingRecord>,
    pub redactions: Vec<RedactionRecord>,
}

impl TenantState {
    pub fn find_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn bump_version(&mut self) {
        self.rule_version += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    pub version: u32,
    /// 新映射写入使用的密钥代次（轮换提升后立即更新）。
    #[serde(default)]
    pub key_generation: u64,
    pub tenants: BTreeMap<String, TenantState>,
}

impl StateFile {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn new() -> Self {
        Self { version: Self::CURRENT_VERSION, key_generation: 0, tenants: BTreeMap::new() }
    }

    pub fn tenant(&self, id: &str) -> Option<&TenantState> {
        self.tenants.get(id)
    }

    pub fn tenant_mut(&mut self, id: &str) -> &mut TenantState {
        self.tenants.entry(id.to_string()).or_default()
    }
}

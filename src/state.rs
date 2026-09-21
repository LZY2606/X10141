use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crypto::KeyFile;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    #[default]
    Literal,
    Regex,
}

fn default_version() -> u32 {
    1
}

fn default_stable() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub kind: MatchKind,
    pub pattern: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub description: String,
    /// true: 同租户 + 规则版本 + 原文 => 稳定 token；false: 每次脱敏生成新 token
    #[serde(default = "default_stable")]
    pub stable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MappingRecord {
    pub token_id: String,
    pub gen: u32,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub created_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub detail: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionEntry {
    pub tenant: String,
    pub redacted_text: String,
    pub token_ids: Vec<String>,
    pub ts: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub rules: Vec<Rule>,
    pub current_gen: u32,
    pub mappings: BTreeMap<String, MappingRecord>,
    pub audit: Vec<AuditRecord>,
    pub redactions: Vec<RedactionEntry>,
}

pub struct Store {
    pub dir: PathBuf,
    pub state: State,
    pub keys: KeyFile,
}

fn keys_path(dir: &Path) -> PathBuf {
    dir.join("keys.json")
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

/// 原子写：先写临时文件并 fsync，再 rename。崩溃时旧文件保持完整。
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_file_name(format!("{}.tmp", path.file_name().unwrap().to_string_lossy()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Store {
    pub fn exists(dir: &Path) -> bool {
        keys_path(dir).is_file() && state_path(dir).is_file()
    }

    pub fn init(dir: &Path, keys: KeyFile) -> io::Result<Store> {
        fs::create_dir_all(dir)?;
        let state = State { current_gen: 1, ..Default::default() };
        let store = Store { dir: dir.to_path_buf(), state, keys };
        store.save_keys()?;
        store.save_state()?;
        Ok(store)
    }

    /// 打开已有仓库。崩溃恢复：残留的 *.tmp 被忽略并清理；
    /// keys.json 可能含有尚未启用的多余代次（轮换第一步完成后崩溃），无害。
    pub fn open(dir: &Path) -> io::Result<Store> {
        let keys_bytes = fs::read(keys_path(dir))?;
        let keys: KeyFile =
            serde_json::from_slice(&keys_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let state_bytes = fs::read(state_path(dir))?;
        let state: State =
            serde_json::from_slice(&state_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        for name in ["keys.json.tmp", "state.json.tmp"] {
            let _ = fs::remove_file(dir.join(name));
        }
        Ok(Store { dir: dir.to_path_buf(), state, keys })
    }

    pub fn save_state(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.state).expect("state serializes");
        atomic_write(&state_path(&self.dir), &bytes)
    }

    pub fn save_keys(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.keys).expect("keys serialize");
        atomic_write(&keys_path(&self.dir), &bytes)
    }
}

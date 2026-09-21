//! 本地密钥库：首次启动生成主密钥；轮换增加新代次，旧代次永久保留用于解密。
//! 所有派生物只存在内存与 0600 权限的本地文件中。

use crate::crypto::{cat, hex, hkdf, FillBytes};
use crate::fsutil::{atomic_write, chmod_600, read_if_exists};
use crate::model::{EngineError, EngineResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const DERIVE_OKM_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPhase {
    /// 新代次密钥已落盘，但尚无映射/审计引用它。
    KeyWritten,
    /// 状态与审计已确认引用新代次。
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationRecord {
    pub id: u64,
    pub seed_hex: String,
    pub created_unix: i64,
    /// 非 None 表示轮换在该阶段后崩溃，重启需要推进到一致状态。
    pub pending: Option<RotationPhase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainFile {
    pub master_hex: String,
    pub audit_key_hex: String,
    pub generations: BTreeMap<u64, GenerationRecord>,
    pub current_generation: u64,
}

#[derive(Debug, Clone)]
pub struct Generation {
    pub id: u64,
    pub seed: Vec<u8>,
    pub created_unix: i64,
    pub pending: Option<RotationPhase>,
}

pub struct Keychain {
    file: KeychainFile,
    gens: BTreeMap<u64, Generation>,
}

impl Keychain {
    pub fn path(dir: &Path) -> std::path::PathBuf {
        dir.join("keychain.json")
    }

    /// 首次启动：生成主密钥、审计密钥与第 1 代派生种子。
    pub fn initialize(dir: &Path, rng: &mut dyn FillBytes, now: i64) -> EngineResult<Self> {
        let path = Self::path(dir);
        if path.exists() {
            return Self::open(dir);
        }
        std::fs::create_dir_all(dir)?;
        let mut master = vec![0u8; 32];
        rng.fill(&mut master);
        // 审计密钥独立于轮换种子，跨代次固定，保证审计链可长期验证。
        let mut audit_key = hkdf(
            b"maskroom-audit-salt-v1",
            &master,
            b"maskroom-audit-key-v1",
            DERIVE_OKM_LEN,
        );
        let mut seed = vec![0u8; 32];
        rng.fill(&mut seed);

        let mut gens = BTreeMap::new();
        gens.insert(
            1,
            Generation { id: 1, seed: seed.clone(), created_unix: now, pending: None },
        );
        let file = KeychainFile {
            master_hex: hex(&master),
            audit_key_hex: hex(&audit_key),
            generations: BTreeMap::from([(
                1,
                GenerationRecord {
                    id: 1,
                    seed_hex: hex(&seed),
                    created_unix: now,
                    pending: None,
                },
            )]),
            current_generation: 1,
        };
        let kc = Keychain { file, gens };
        kc.persist_to(&dir)?;
        // 立刻擦除临时派生缓冲。
        for b in audit_key.iter_mut() {
            *b = 0;
        }
        Ok(kc)
    }

    pub fn open(dir: &Path) -> EngineResult<Self> {
        let file: KeychainFile = read_if_exists(&Self::path(dir))?
            .ok_or_else(|| EngineError::Corrupt("密钥库不存在".into()))?;
        let mut gens = BTreeMap::new();
        for (id, rec) in &file.generations {
            let seed = crate::crypto::unhex(&rec.seed_hex)
                .ok_or_else(|| EngineError::Corrupt("代次种子编码损坏".into()))?;
            if *id != rec.id || seed.len() != 32 {
                return Err(EngineError::Corrupt("代次记录不一致".into()));
            }
            gens.insert(*id, Generation {
                id: rec.id,
                seed,
                created_unix: rec.created_unix,
                pending: rec.pending,
            });
        }
        if !gens.contains_key(&file.current_generation) {
            return Err(EngineError::Corrupt("当前代次缺失".into()));
        }
        Ok(Keychain { file, gens })
    }

    fn persist_to(&self, dir: &Path) -> EngineResult<()> {
        atomic_write(&Self::path(dir), &serde_json::to_vec_pretty(&self.file).unwrap(), true)?;
        let _ = chmod_600(&Self::path(dir));
        Ok(())
    }

    pub fn audit_key(&self) -> Vec<u8> {
        crate::crypto::unhex(&self.file.audit_key_hex).expect("审计密钥合法")
    }

    pub fn current(&self) -> &Generation {
        &self.gens[&self.file.current_generation]
    }

    pub fn current_id(&self) -> u64 {
        self.file.current_generation
    }

    pub fn generation(&self, id: u64) -> Option<&Generation> {
        self.gens.get(&id)
    }

    pub fn generation_ids(&self) -> Vec<u64> {
        self.gens.keys().copied().collect()
    }

    /// 轮换第 1 阶段：仅写入新代次（pending=KeyWritten），不动当前代次。
    pub fn rotate_write_new(
        &mut self,
        dir: &Path,
        rng: &mut dyn FillBytes,
        now: i64,
    ) -> EngineResult<u64> {
        let new_id = self.file.current_generation + 1;
        let mut seed = vec![0u8; 32];
        rng.fill(&mut seed);
        self.file.generations.insert(
            new_id,
            GenerationRecord {
                id: new_id,
                seed_hex: hex(&seed),
                created_unix: now,
                pending: Some(RotationPhase::KeyWritten),
            },
        );
        self.gens.insert(
            new_id,
            Generation { id: new_id, seed, created_unix: now, pending: Some(RotationPhase::KeyWritten) },
        );
        self.persist_to(dir)?;
        Ok(new_id)
    }

    /// 轮换第 2 阶段：把新代次提升为当前（仍保留 pending 标记直到审计/状态完成）。
    pub fn rotate_promote(&mut self, dir: &Path, new_id: u64) -> EngineResult<()> {
        if !self.gens.contains_key(&new_id) {
            return Err(EngineError::Corrupt("待提升代次不存在".into()));
        }
        self.file.current_generation = new_id;
        if let Some(rec) = self.file.generations.get_mut(&new_id) {
            rec.pending = Some(RotationPhase::KeyWritten);
        }
        if let Some(g) = self.gens.get_mut(&new_id) {
            g.pending = Some(RotationPhase::KeyWritten);
        }
        self.persist_to(dir)?;
        Ok(())
    }

    /// 轮换第 3 阶段：清除 pending，标记完成；此后新写入只用新代次。
    pub fn rotate_commit(&mut self, dir: &Path, new_id: u64) -> EngineResult<()> {
        if let Some(rec) = self.file.generations.get_mut(&new_id) {
            rec.pending = None;
        }
        if let Some(g) = self.gens.get_mut(&new_id) {
            g.pending = None;
        }
        self.persist_to(dir)?;
        Ok(())
    }

    /// 丢弃尚未提升、也没有任何数据引用的新代次（崩溃回滚）。
    pub fn discard_generation(&mut self, dir: &Path, id: u64) -> EngineResult<()> {
        if self.file.current_generation >= id {
            return Err(EngineError::Conflict("代次已提升，不能丢弃".into()));
        }
        self.file.generations.remove(&id);
        self.gens.remove(&id);
        self.persist_to(dir)
    }

    /// 找到任一未完成代次（崩溃恢复用）。
    pub fn pending_generation(&self) -> Option<Generation> {
        self.gens
            .values()
            .find(|g| g.pending.is_some())
            .cloned()
    }

    pub fn is_promoted(&self, id: u64) -> bool {
        self.file.current_generation >= id
    }

    // ---- 派生密钥（每代次、每租户、每用途独立）----

    fn derive(&self, gen: &Generation, tenant: &str, purpose: &[u8]) -> Vec<u8> {
        let salt = cat(&[b"maskroom-derive-salt-v1", &gen.id.to_be_bytes()]);
        let info = cat(&[
            b"maskroom-tenant-key-v1",
            tenant.as_bytes(),
            purpose,
            &gen.id.to_be_bytes(),
        ]);
        hkdf(&salt, &gen.seed, &info, DERIVE_OKM_LEN)
    }

    pub fn token_tag_key(&self, gen_id: u64, tenant: &str) -> EngineResult<Vec<u8>> {
        let g = self
            .generation(gen_id)
            .ok_or_else(|| EngineError::InvalidToken)?;
        Ok(self.derive(g, tenant, b"token-tag"))
    }

    pub fn stable_id_key(&self, gen_id: u64, tenant: &str) -> EngineResult<Vec<u8>> {
        let g = self
            .generation(gen_id)
            .ok_or_else(|| EngineError::InvalidToken)?;
        Ok(self.derive(g, tenant, b"stable-record-id"))
    }

    pub fn data_key(&self, gen_id: u64, tenant: &str) -> EngineResult<Vec<u8>> {
        let g = self
            .generation(gen_id)
            .ok_or_else(|| EngineError::InvalidToken)?;
        Ok(self.derive(g, tenant, b"mapping-data"))
    }
}

/// 加密映射的 AAD（绑定代次、租户、记录 ID，防跨记录/跨租户搬运）。
pub fn mapping_aad(gen_id: u64, tenant: &str, record_id_b64: &str) -> Vec<u8> {
    cat(&[
        b"maskroom-mapping-aad-v1",
        &gen_id.to_be_bytes(),
        tenant.as_bytes(),
        record_id_b64.as_bytes(),
    ])
}

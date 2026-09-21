#![allow(dead_code)]
//! 测试公共设施：确定性 RNG、固定时钟、临时数据目录。

use gsb_maskroom::audit::{Clock, FixedClock};
use gsb_maskroom::crypto::{DeterministicFill, FillBytes};
use gsb_maskroom::engine::Engine;
use std::path::PathBuf;
use std::sync::Arc;

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("maskroom-test-{tag}-{pid}-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn deterministic_rng(seed: &[u8]) -> Box<dyn FillBytes + Send> {
    Box::new(DeterministicFill::new(seed))
}

pub fn fixed_clock(start: i64) -> Arc<dyn Clock + Send + Sync> {
    Arc::new(FixedClock::new(start))
}

pub fn test_engine(tag: &str, seed: &[u8]) -> (TempDir, Engine) {
    let dir = TempDir::new(tag);
    let engine =
        Engine::open_with_test(dir.path(), fixed_clock(1_700_000_000), deterministic_rng(seed))
            .unwrap();
    (dir, engine)
}

pub fn reopen(dir: &std::path::Path, seed: &[u8], clock: Arc<dyn Clock + Send + Sync>) -> Engine {
    Engine::open_with_test(dir, clock, deterministic_rng(seed)).unwrap()
}

//! 本地持久化辅助：临时文件 + rename 原子写、0600 权限。

use crate::model::{EngineError, EngineResult};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub fn chmod_600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn chmod_600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn chmod_700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn chmod_700(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// 写入同目录临时文件，fsync 后 rename，目录再 fsync，保证崩溃时不留半个文件。
pub fn atomic_write(path: &Path, contents: &[u8], secret: bool) -> EngineResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| EngineError::Io(e.to_string()))?;
    }
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    tmp_name.push_str(".tmp-");
    tmp_name.push_str(&random_suffix());
    let tmp_path: PathBuf = path.parent().unwrap_or_else(|| Path::new(".")).join(tmp_name);

    {
        let mut f = File::create(&tmp_path).map_err(|e| EngineError::Io(e.to_string()))?;
        f.write_all(contents).map_err(|e| EngineError::Io(e.to_string()))?;
        f.flush().map_err(|e| EngineError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| EngineError::Io(e.to_string()))?;
    }
    if secret {
        chmod_600(&tmp_path).map_err(|e| EngineError::Io(e.to_string()))?;
    }
    std::fs::rename(&tmp_path, path).map_err(|e| EngineError::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn random_suffix() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut bytes);
    crate::crypto::hex(&bytes)
}

pub fn read_if_exists<T: serde::de::DeserializeOwned>(path: &Path) -> EngineResult<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(path).map_err(|e| EngineError::Io(e.to_string()))?;
    let value = serde_json::from_slice(&data)
        .map_err(|e| EngineError::Corrupt(format!("解析 {} 失败：{e}", path.display())))?;
    Ok(Some(value))
}

//! 本地密钥与加解密原语。不依赖任何外部密钥服务：
//! 主密钥在首次真实启动时本地生成，测试使用确定的固定密钥。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("非法 hex 字符: {}", c as char)),
    }
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err("hex 长度必须为偶数".to_string());
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Ok(out)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 本地主密钥。所有派生密钥（租户 token 密钥、各代次加密密钥）
/// 都由它单向派生，轮换只是递增代次编号，无需重存旧密钥。
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        MasterKey(k)
    }

    pub fn from_bytes(k: [u8; 32]) -> Self {
        MasterKey(k)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let v = hex_decode(s)?;
        if v.len() != 32 {
            return Err("主密钥必须为 32 字节（64 个 hex 字符）".to_string());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&v);
        Ok(MasterKey(k))
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    fn derive(&self, label: &str) -> [u8; 32] {
        hmac_sha256(&self.0, label.as_bytes())
    }

    /// 每个租户独立的 token 派生密钥：不同租户对同一原文产生不可关联的 token。
    pub fn tenant_key(&self, tenant: &str) -> [u8; 32] {
        self.derive(&format!("masking-room/tenant/v1/{tenant}"))
    }

    /// 某一代次的数据加密密钥。
    fn enc_key(&self, gen: u64) -> [u8; 32] {
        self.derive(&format!("masking-room/enc/v1/gen/{gen}"))
    }

    pub fn encrypt(&self, gen: u64, plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
        let key = self.enc_key(gen);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32 字节密钥");
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("AES-GCM 加密不会失败");
        (nonce, ct)
    }

    pub fn decrypt(&self, gen: u64, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("nonce 长度必须为 12 字节".to_string());
        }
        let key = self.enc_key(gen);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32 字节密钥");
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| "密文校验失败（数据被篡改或代次不符）".to_string())
    }
}

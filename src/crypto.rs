//! 全部本地完成的密码学原语：HKDF-SHA256、HMAC-SHA256、AES-256-GCM。
//! 不接触任何外部密钥服务。

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub type HmacSha256 = Hmac<Sha256>;

pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

/// 拼接 `len_be32 || data`，保证多段编码无歧义。
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// RFC 5869 HKDF-Extract + Expand（SHA-256，单块扩展足够 32 字节输出）。
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 32, "本项目只需要不超过一个哈希块的派生输出");
    let mut extract = <HmacSha256 as Mac>::new_from_slice(salt).expect("hmac");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk).expect("hmac");
    expand.update(info);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes().to_vec();
    okm[..out_len].to_vec()
}

/// AES-256-GCM 加密；`nonce` 必须为 12 字节且每次唯一。
pub fn seal(key256: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(key256).expect("32 字节密钥");
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("GCM 加密不会失败")
}

pub fn open(key256: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<()> {
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(key256).expect("32 字节密钥");
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .ok()
        .map(|_| ())
}

/// 常量时间比较。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// 随机性来源抽象：生产用操作系统 CSPRNG，测试可注入确定性实现。
pub trait FillBytes {
    fn fill(&mut self, out: &mut [u8]);
}

pub struct OsFill;

impl FillBytes for OsFill {
    fn fill(&mut self, out: &mut [u8]) {
        OsRng.fill_bytes(out);
    }
}

/// 基于 HMAC-SHA256 计数模式的确定性 RNG（仅测试使用）。
pub struct DeterministicFill {
    key: Vec<u8>,
    counter: u64,
}

impl DeterministicFill {
    pub fn new(seed: &[u8]) -> Self {
        Self { key: hmac(b"deterministic-fill-v1", &[seed]), counter: 0 }
    }
}

impl FillBytes for DeterministicFill {
    fn fill(&mut self, out: &mut [u8]) {
        let mut written = 0;
        while written < out.len() {
            let block = hmac(&self.key, &[&self.counter.to_be_bytes()]);
            let take = block.len().min(out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            self.counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_known_case() {
        // RFC 5869 Test Case 1 的前若干字节（单块输出）。
        let ikm = [0x0bu8; 22];
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf(&salt, &ikm, &info, 32);
        // RFC 5869 Test Case 1 OKM 前 32 字节。
        assert_eq!(hex(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
    }

    #[test]
    fn gcm_roundtrip_and_aad() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = seal(&key, &nonce, b"aad", b"secret");
        assert!(open(&key, &nonce, b"aad", &ct).is_some());
        assert!(open(&key, &nonce, b"other", &ct).is_none());
        assert!(open(&key, &[2u8; 12], b"aad", &ct).is_none());
    }

    #[test]
    fn deterministic_fill_is_stable() {
        let mut a = DeterministicFill::new(b"seed");
        let mut b = DeterministicFill::new(b"seed");
        let mut xa = [0u8; 50];
        let mut xb = [0u8; 50];
        a.fill(&mut xa);
        b.fill(&mut xb);
        assert_eq!(xa, xb);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        unhex(s).unwrap()
    }
}

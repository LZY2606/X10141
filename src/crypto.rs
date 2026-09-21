use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn b64e(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64d(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenKey {
    pub id: u32,
    pub key_b64: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub master_b64: String,
    pub generations: Vec<GenKey>,
}

impl KeyFile {
    pub fn generate() -> Self {
        let mut master = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut master);
        let mut gen = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut gen);
        KeyFile {
            master_b64: b64e(&master),
            generations: vec![GenKey { id: 1, key_b64: b64e(&gen) }],
        }
    }

    pub fn deterministic(master: [u8; 32], gen: [u8; 32]) -> Self {
        KeyFile {
            master_b64: b64e(&master),
            generations: vec![GenKey { id: 1, key_b64: b64e(&gen) }],
        }
    }

    pub fn master(&self) -> [u8; 32] {
        let v = b64d(&self.master_b64).expect("master key must be valid base64");
        v.try_into().expect("master key must be 32 bytes")
    }

    pub fn key_for(&self, id: u32) -> Option<[u8; 32]> {
        self.generations
            .iter()
            .find(|g| g.id == id)
            .and_then(|g| b64d(&g.key_b64).ok())
            .and_then(|v| v.try_into().ok())
    }

    pub fn add_generation(&mut self) -> u32 {
        let id = self.generations.iter().map(|g| g.id).max().unwrap_or(0) + 1;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        self.generations.push(GenKey { id, key_b64: b64e(&key) });
        id
    }
}

fn feed(mac: &mut HmacSha256, part: &[u8]) {
    mac.update(&(part.len() as u64).to_be_bytes());
    mac.update(part);
}

/// 稳定 token：HMAC(master, tenant | rule | version | plaintext [| salt])。
/// 不同租户的 token 由同一主密钥派生但输入含租户标识，彼此不可关联。
pub fn token_id(
    master: &[u8],
    tenant: &str,
    rule_id: &str,
    version: u32,
    plaintext: &str,
    salt: Option<&[u8]>,
) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master).expect("hmac accepts any key length");
    feed(&mut mac, b"token-v1");
    feed(&mut mac, tenant.as_bytes());
    feed(&mut mac, rule_id.as_bytes());
    feed(&mut mac, &version.to_be_bytes());
    feed(&mut mac, plaintext.as_bytes());
    if let Some(s) = salt {
        feed(&mut mac, s);
    }
    let out = mac.finalize().into_bytes();
    b64e(&out[..16])
}

pub fn encrypt(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .expect("aead encrypt");
    (b64e(&nonce), b64e(&ct))
}

pub fn decrypt(key: &[u8; 32], aad: &str, nonce_b64: &str, ct_b64: &str) -> Result<Vec<u8>, String> {
    let nonce = b64d(nonce_b64)?;
    let ct = b64d(ct_b64)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| "aead decrypt failed".to_string())
}

//! 无外部依赖的密码学原语：SHA-256、HMAC、HKDF、AES-256-CTR 与加密封包。
//!
//! 封包格式（全部小端长度）：
//! `MRMv1 || u8 gen_len || gen_bytes || 12B nonce || ciphertext || 32B mac`
//! MAC = HMAC-SHA256(mac_key, header || nonce || ciphertext || aad)，加密后认证。

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const MAC_LEN: usize = 32;
const MAGIC: &[u8; 5] = b"MRMv1";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Sha256::new();
    ctx.update(data);
    ctx.finalize()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut norm = [0u8; 64];
    if key.len() <= 64 {
        norm[..key.len()].copy_from_slice(key);
    } else {
        let h = sha256(key);
        norm.copy_from_slice(&h);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= norm[i];
        opad[i] ^= norm[i];
    }
    let mut ctx = Sha256::new();
    ctx.update(&ipad);
    ctx.update(data);
    let inner = ctx.finalize();
    let mut ctx = Sha256::new();
    ctx.update(&opad);
    ctx.update(&inner);
    ctx.finalize()
}

/// HMAC 截断（对每个分片带长度前缀，避免二义拼接），用于稳定 token 指纹。
pub fn hmac_truncated(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut norm = [0u8; 64];
    if key.len() <= 64 {
        norm[..key.len()].copy_from_slice(key);
    } else {
        norm.copy_from_slice(&sha256(key));
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= norm[i];
        opad[i] ^= norm[i];
    }
    let mut ctx = Sha256::new();
    ctx.update(&ipad);
    for p in parts {
        ctx.update(&(p.len() as u64).to_le_bytes());
        ctx.update(p);
    }
    let inner = ctx.finalize();
    let mut ctx2 = Sha256::new();
    ctx2.update(&opad);
    ctx2.update(&inner);
    let full = ctx2.finalize();
    out.copy_from_slice(&full[..out.len()]);
}

/// HKDF-SHA256（RFC 5869），salt 缺省为全零 32 字节。
pub fn hkdf(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    debug_assert!(out.len() <= 32 * 255);
    let salt = [0u8; 32];
    let prk = hmac_sha256(&salt, ikm);
    let mut t = Vec::new();
    let mut pos = 0;
    let mut counter = 1u8;
    while pos < out.len() {
        let mut data = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        t = hmac_sha256(&prk, &data).to_vec();
        let take = (out.len() - pos).min(32);
        out[pos..pos + take].copy_from_slice(&t[..take]);
        pos += take;
        counter += 1;
    }
}

/// 从主密钥派生加密/认证密钥对。
pub fn derive_seal_keys(master: &[u8; KEY_LEN], gen: &str) -> ([u8; 32], [u8; 32]) {
    let mut buf = [0u8; 64];
    let mut info = Vec::new();
    info.extend_from_slice(b"masking-room seal v1|gen=");
    info.extend_from_slice(gen.as_bytes());
    hkdf(master, &info, &mut buf);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&buf[..32]);
    mac.copy_from_slice(&buf[32..]);
    (enc, mac)
}

pub struct Sealed {
    pub gen: String,
    pub blob: Vec<u8>,
}

pub fn seal<R: crate::rng::Rng>(
    rng: &mut R,
    gen: &str,
    master: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Sealed> {
    let (enc, mac_key) = derive_seal_keys(master, gen);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let mut ciphertext = plaintext.to_vec();
    aes256_ctr_xor(&enc, &nonce, &mut ciphertext);

    let mut blob = Vec::with_capacity(5 + 1 + gen.len() + NONCE_LEN + ciphertext.len() + MAC_LEN);
    blob.extend_from_slice(MAGIC);
    let gen_bytes = gen.as_bytes();
    if gen_bytes.len() > 255 {
        return Err(Error::crypto("generation id too long"));
    }
    blob.push(gen_bytes.len() as u8);
    blob.extend_from_slice(gen_bytes);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    let mut mac_input = Vec::with_capacity(blob.len() + aad.len());
    mac_input.extend_from_slice(&blob);
    mac_input.extend_from_slice(aad);
    let tag = hmac_sha256(&mac_key, &mac_input);
    blob.extend_from_slice(&tag);
    Ok(Sealed {
        gen: gen.to_string(),
        blob,
    })
}

pub fn open(
    master_by_gen: &std::collections::BTreeMap<String, [u8; KEY_LEN]>,
    blob: &[u8],
    aad: &[u8],
) -> Result<(String, Vec<u8>)> {
    if blob.len() < 5 + 1 + NONCE_LEN + MAC_LEN || &blob[..5] != MAGIC {
        return Err(Error::crypto("malformed sealed blob"));
    }
    let gen_len = blob[5] as usize;
    let header_end = 6 + gen_len;
    if blob.len() < header_end + NONCE_LEN + MAC_LEN {
        return Err(Error::crypto("malformed sealed blob"));
    }
    let gen = std::str::from_utf8(&blob[6..header_end])
        .map_err(|_| Error::crypto("bad generation id"))?
        .to_string();
    let master = master_by_gen
        .get(&gen)
        .ok_or_else(|| Error::crypto("no key for generation"))?;
    let (enc, mac_key) = derive_seal_keys(master, &gen);
    let mac_at = blob.len() - MAC_LEN;
    let mut mac_input = Vec::with_capacity(mac_at + aad.len());
    mac_input.extend_from_slice(&blob[..mac_at]);
    mac_input.extend_from_slice(aad);
    let expected = hmac_sha256(&mac_key, &mac_input);
    if !constant_time_eq(&expected, &blob[mac_at..]) {
        return Err(Error::crypto("authentication failed"));
    }
    let nonce: [u8; NONCE_LEN] = blob[header_end..header_end + NONCE_LEN]
        .try_into()
        .unwrap();
    let mut plaintext = blob[header_end + NONCE_LEN..mac_at].to_vec();
    aes256_ctr_xor(&enc, &nonce, &mut plaintext);
    Ok((gen, plaintext))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    length: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add((data.len() as u64) * 8);
        let mut data = data;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buf_len] = 0x80;
        for b in &mut self.buffer[self.buf_len + 1..] {
            *b = 0;
        }
        if self.buf_len + 1 + 8 > 64 {
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0u8; 64];
        }
        let len_pos = 56;
        self.buffer[len_pos..].copy_from_slice(&self.length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// AES-256 仅前向分组（CTR 模式只需加密）。S 盒在构造时由 GF(2^8) 逆元+仿射变换生成。
pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
    sbox: [u8; 256],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let sbox = build_sbox();
        let mut round_keys = [[0u8; 16]; 15];
        round_keys[0].copy_from_slice(&key[..16]);
        round_keys[1].copy_from_slice(&key[16..]);
        let rcon = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        for i in 2..15 {
            let mut temp = round_keys[i - 1];
            if i % 2 == 0 {
                temp.rotate_left(1);
                for b in temp.iter_mut() {
                    *b = sbox[*b as usize];
                }
                temp[0] ^= rcon[i / 2 - 1];
            }
            for j in 0..16 {
                round_keys[i][j] = round_keys[i - 2][j] ^ temp[j];
            }
        }
        Aes256 { round_keys, sbox }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0]);
        for round in 1..14 {
            sub_bytes(block, &self.sbox);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round]);
        }
        sub_bytes(block, &self.sbox);
        shift_rows(block);
        add_round_key(block, &self.round_keys[14]);
    }
}

fn build_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for i in 0u16..256 {
        let inv = if i == 0 { 0 } else { gf_inverse(i as u8) };
        let mut x = inv;
        let mut y = x
            ^ x.rotate_left(1)
            ^ x.rotate_left(2)
            ^ x.rotate_left(3)
            ^ x.rotate_left(4)
            ^ 0x63;
        y &= 0xff;
        sbox[i as usize] = y;
    }
    sbox
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

fn gf_inverse(x: u8) -> u8 {
    for y in 1u16..256 {
        if gf_mul(x, y as u8) == 1 {
            return y as u8;
        }
    }
    0
}

fn add_round_key(block: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        block[i] ^= key[i];
    }
}

fn sub_bytes(block: &mut [u8; 16], sbox: &[u8; 256]) {
    for b in block.iter_mut() {
        *b = sbox[*b as usize];
    }
}

fn shift_rows(block: &mut [u8; 16]) {
    let original = *block;
    for r in 1..4 {
        for c in 0..4 {
            block[r + 4 * c] = original[r + 4 * ((c + r) % 4)];
        }
    }
}

fn mix_columns(block: &mut [u8; 16]) {
    for c in 0..4 {
        let col = c * 4;
        let a0 = block[col];
        let a1 = block[col + 1];
        let a2 = block[col + 2];
        let a3 = block[col + 3];
        block[col] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        block[col + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        block[col + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        block[col + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

/// AES-256-CTR 异或：nonce 12 字节 + 大端 32 位计数器。
pub fn aes256_ctr_xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let aes = Aes256::new(key);
    let mut counter = 0u32;
    let mut pos = 0;
    while pos < data.len() {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(nonce);
        block[12..].copy_from_slice(&counter.to_be_bytes());
        aes.encrypt_block(&mut block);
        let take = (data.len() - pos).min(16);
        for i in 0..take {
            data[pos + i] ^= block[i];
        }
        pos += take;
        counter = counter.wrapping_add(1);
    }
}

const B32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

pub fn base32hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            out.push(B32HEX[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(B32HEX[idx] as char);
    }
    out
}

pub fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        let v = match c {
            '0'..='9' => c as u64 - '0' as u64,
            'a'..='v' => c as u64 - 'a' as u64 + 10,
            'A'..='V' => c as u64 - 'A' as u64 + 10,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let got = sha256(b"abc");
        let expect = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex_encode(&got), expect);
    }

    #[test]
    fn aes256_fips_197_vector() {
        let key: [u8; 32] = (0..32u8).collect::<Vec<_>>().try_into().unwrap();
        let aes = Aes256::new(&key);
        let mut block = [0u8; 16];
        aes.encrypt_block(&mut block);
        let expect = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        assert_eq!(block, expect);
    }

    #[test]
    fn ctr_roundtrip() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let data = b"the quick brown fox jumps over the lazy dog, twice the quick brown fox";
        let mut enc = data.to_vec();
        aes256_ctr_xor(&key, &nonce, &mut enc);
        assert_ne!(enc, data);
        aes256_ctr_xor(&key, &nonce, &mut enc);
        assert_eq!(enc, data);
    }

    #[test]
    fn seal_open_roundtrip_and_aad() {
        let mut rng = crate::rng::DeterministicRng::from_seed(1);
        let master = [9u8; 32];
        let sealed = seal(&mut rng, "g1", &master, b"secret", b"aad-1").unwrap();
        let mut map = std::collections::BTreeMap::new();
        map.insert("g1".to_string(), master);
        let (g, pt) = open(&map, &sealed.blob, b"aad-1").unwrap();
        assert_eq!(g, "g1");
        assert_eq!(pt, b"secret");
        assert!(open(&map, &sealed.blob, b"aad-2").is_err());
        let mut tampered = sealed.blob.clone();
        let n = tampered.len() - 40;
        tampered[n] ^= 1;
        assert!(open(&map, &tampered, b"aad-1").is_err());
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}

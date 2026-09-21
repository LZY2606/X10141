//! 随机数抽象：生产环境使用 OS CSPRNG 播种 ChaCha20，测试使用确定性种子。

pub trait Rng {
    fn fill(&mut self, dest: &mut [u8]);
}

/// 生产用随机数：每次创建都混入 OS 熵与时间，内部用 ChaCha20 生成字节流。
pub struct OsRng {
    inner: ChaCha20Rng,
}

impl OsRng {
    pub fn new() -> Self {
        use std::time::SystemTime;
        let mut seed = [0u8; 32];
        getrandom(&mut seed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let tid = {
            let p: *const u8 = &nanos as *const _ as *const u8;
            p as u128
        };
        let mix = (nanos ^ pid ^ tid).to_le_bytes();
        for (b, x) in seed.iter_mut().zip(mix.iter().cycle()) {
            b ^= x;
        }
        OsRng {
            inner: ChaCha20Rng::new(seed),
        }
    }
}

impl Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) {
        self.inner.fill(dest);
    }
}

#[cfg(unix)]
fn getrandom(dest: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(dest).expect("read /dev/urandom");
}

#[cfg(not(unix))]
fn getrandom(dest: &mut [u8]) {
    // 非 Unix 环境的回退：弱熵来源，仅保证不崩溃（本项目主要在 macOS/Linux 演示）。
    use std::time::SystemTime;
    let mut x = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15);
    for b in dest.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
}

/// 确定性 RNG：splitmix64 播种 32 字节，再用 ChaCha20 扩展成字节流。
pub struct DeterministicRng {
    inner: ChaCha20Rng,
}

impl DeterministicRng {
    pub fn from_seed(seed: u64) -> Self {
        let mut key = [0u8; 32];
        let mut x = seed;
        for chunk in key.chunks_mut(8) {
            x = splitmix64(x);
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        DeterministicRng {
            inner: ChaCha20Rng::new(key),
        }
    }
}

impl Rng for DeterministicRng {
    fn fill(&mut self, dest: &mut [u8]) {
        self.inner.fill(dest);
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// 最小 ChaCha20 实现（RFC 8439）。
struct ChaCha20Rng {
    key: [u8; 32],
    counter: u32,
    nonce: [u8; 12],
}

impl ChaCha20Rng {
    fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng {
            key: seed,
            counter: 0,
            nonce: [0; 12],
        };
        rng.reseed_mix();
        rng
    }

    fn reseed_mix(&mut self) {
        let mut block = [0u8; 64];
        chacha20_block(&self.key, self.counter, &self.nonce, &mut block);
        let mut k = [0u8; 32];
        let mut n = [0u8; 12];
        k.copy_from_slice(&block[..32]);
        n.copy_from_slice(&block[32..44]);
        self.key = k;
        self.nonce = n;
        self.counter = 0;
    }
}

impl Rng for ChaCha20Rng {
    fn fill(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            let mut block = [0u8; 64];
            chacha20_block(&self.key, self.counter, &self.nonce, &mut block);
            let take = (dest.len() - written).min(64);
            dest[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            self.counter = self.counter.wrapping_add(1);
            if self.counter == 0 {
                self.reseed_mix();
            }
        }
    }
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let constants = [0x61707865u32, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&constants);
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter;
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut work = state;
    for _ in 0..10 {
        quarter_round(&mut work, 0, 4, 8, 12);
        quarter_round(&mut work, 1, 5, 9, 13);
        quarter_round(&mut work, 2, 6, 10, 14);
        quarter_round(&mut work, 3, 7, 11, 15);
        quarter_round(&mut work, 0, 5, 10, 15);
        quarter_round(&mut work, 1, 6, 11, 12);
        quarter_round(&mut work, 2, 7, 8, 13);
        quarter_round(&mut work, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let v = work[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_is_stable() {
        let mut a = DeterministicRng::from_seed(42);
        let mut b = DeterministicRng::from_seed(42);
        let mut xa = [0u8; 40];
        let mut xb = [0u8; 40];
        a.fill(&mut xa);
        b.fill(&mut xb);
        assert_eq!(xa, xb);
        let mut c = DeterministicRng::from_seed(43);
        let mut xc = [0u8; 40];
        c.fill(&mut xc);
        assert_ne!(xa, xc);
    }

    #[test]
    fn chacha_known_vector() {
        // RFC 8439 Section 2.3.2
        let key: [u8; 32] = (0..32u8).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut block = [0u8; 64];
        chacha20_block(&key, 1, &nonce, &mut block);
        assert_eq!(block[0..4], [0x10, 0xf1, 0xe7, 0xe4]);
        assert_eq!(block[12], 0x7f);
        assert_eq!(block[63], 0x00);
    }
}

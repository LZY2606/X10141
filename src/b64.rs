//! 无填充的 URL 安全 base64（token 专用字母表，且不含 `_`/`-` 之外的特殊字符）。

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*~";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let b2 = input[i + 2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        out.push(ALPHABET[(n & 63) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        0 => {}
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        _ => unreachable!(),
    }
    out
}

pub fn decode(input: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(input.len());
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'*' => 62,
            b'~' => 63,
            _ => return None,
        };
        vals.push(v as u32);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    let mut i = 0;
    while i < vals.len() {
        let chunk = vals.len() - i;
        if chunk == 1 {
            return None;
        }
        let n0 = vals[i];
        let n1 = vals[i + 1];
        let n2 = if chunk >= 3 { vals[i + 2] } else { 0 };
        let n3 = if chunk >= 4 { vals[i + 3] } else { 0 };
        let n = (n0 << 18) | (n1 << 12) | (n2 << 6) | n3;
        out.push(((n >> 16) & 255) as u8);
        if chunk >= 3 {
            out.push(((n >> 8) & 255) as u8);
        }
        if chunk >= 4 {
            out.push((n & 255) as u8);
        }
        if chunk == 2 && (n & 0xF000) != 0 {
            return None;
        }
        if chunk == 3 && (n & 0xC0) != 0 {
            return None;
        }
        i += 4;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let s = encode(&data);
            assert_eq!(decode(&s).unwrap(), data);
        }
        assert_eq!(encode(&[0xff]), "~w");
        assert_eq!(decode("~w").unwrap(), vec![0xff]);
        assert!(decode("~8").is_none());
        assert_eq!(decode("A").is_none(), true);
    }
}

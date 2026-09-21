//! 替代 token 格式与识别：`MTKN-G{代次}-<22字符ID>-<11字符标签>`。
//! 固定结构使再次处理时可以可靠认出并跳过 token 自身。

use crate::b64;
use crate::crypto::{cat, ct_eq, hmac};

// 不用外部依赖：模块内常量。
const PREFIX: &str = "MTKN-G";
const ID_LEN: usize = 16; // 128 位
const TAG_LEN: usize = 8; // 截断 HMAC，防伪造且体积小

pub fn token_tag(tag_key: &[u8], gen: u64, tenant: &str, id: &[u8]) -> Vec<u8> {
    let full = hmac(
        tag_key,
        &[b"maskroom-token-tag-v1", &gen.to_be_bytes(), tenant.as_bytes(), id],
    );
    full[..TAG_LEN].to_vec()
}

pub fn build(gen: u64, id: &[u8], tag: &[u8]) -> String {
    assert_eq!(id.len(), ID_LEN);
    assert_eq!(tag.len(), TAG_LEN);
    format!("{PREFIX}{}-{}-{}", gen, b64::encode(id), b64::encode(tag))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    pub gen: u64,
    pub id: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn parse(s: &str) -> Option<ParsedToken> {
    let rest = s.strip_prefix(PREFIX)?;
    let mut parts = rest.splitn(3, '-');
    let gen_str = parts.next()?;
    let id_str = parts.next()?;
    let tag_str = parts.next()?;
    if gen_str.is_empty() || gen_str.len() > 20 {
        return None;
    }
    let gen: u64 = gen_str.parse().ok()?;
    if gen == 0 {
        return None;
    }
    if id_str.len() != 22 || tag_str.len() != 11 {
        return None;
    }
    let id = b64::decode(id_str)?;
    let tag = b64::decode(tag_str)?;
    if id.len() != ID_LEN || tag.len() != TAG_LEN {
        return None;
    }
    Some(ParsedToken { gen, id, tag })
}

fn is_token_alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'*' || b == b'~' || b == b'-'
}

/// 找出文本中所有结构合法的候选 token（含字节区间）；标签校验由调用方按租户完成。
/// token 字符全为 ASCII，因此沿 ASCII token 字母表推进，绝不切到多字节字符中间。
pub fn scan(text: &str) -> Vec<(usize, usize, ParsedToken)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(PREFIX) {
        let start = search_from + rel;
        // 从起点开始的最长 ASCII token 字母表连续段（多字节 UTF-8 字节自然不在字母表中）。
        let hard_max = (start + 6 + 20 + 1 + 22 + 1 + 11).min(bytes.len());
        let mut run_end = start;
        while run_end < hard_max && is_token_alphabet(bytes[run_end]) {
            run_end += 1;
        }
        // 选最长的、能成功解析的候选（即 G{gen}-id-tag 整段）。
        let mut found: Option<(usize, ParsedToken)> = None;
        if run_end > start {
            let slice = &text[start..run_end];
            if let Some(t) = parse(slice) {
                found = Some((run_end, t));
            }
        }
        if let Some((end, t)) = found {
            let left_ok = start == 0 || !is_token_alphabet(bytes[start - 1]);
            let right_ok = end == bytes.len() || !is_token_alphabet(bytes[end]);
            if left_ok && right_ok {
                out.push((start, end, t));
            }
            search_from = end;
        } else {
            search_from = start + PREFIX.len();
        }
    }
    out
}

/// 用租户在各代次的标签密钥验证 token；成功返回其记录 ID 的 b64。
pub fn verify_for_tenant(
    t: &ParsedToken,
    tenant: &str,
    gen_ids: &[u64],
    tag_key_for: &dyn Fn(u64) -> Option<Vec<u8>>,
) -> Option<(String, Vec<u8>)> {
    if !gen_ids.contains(&t.gen) {
        return None;
    }
    let key = tag_key_for(t.gen)?;
    let expected = token_tag(&key, t.gen, tenant, &t.id);
    if ct_eq(&expected, &t.tag) {
        Some((b64::encode(&t.id), t.id.clone()))
    } else {
        None
    }
}

/// 稳定记录 ID：同租户 + 同规则版本 + 同原文，在同一密钥代次下恒定。
/// 派生密钥本身按代次隔离，因此轮换后旧原文会自然得到新 ID。
pub fn stable_record_id(stable_id_key: &[u8], rule_version: u64, original: &str) -> Vec<u8> {
    let input = cat(&[b"maskroom-stable-id-v1", &rule_version.to_be_bytes(), original.as_bytes()]);
    let full = hmac(stable_id_key, &[input.as_slice()]);
    full[..ID_LEN].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_scan() {
        let id = [3u8; 16];
        let tag = [9u8; 8];
        let tok = build(7, &id, &tag);
        assert!(tok.starts_with("MTKN-G7-"));
        let p = parse(&tok).unwrap();
        assert_eq!(p.gen, 7);
        assert_eq!(p.id, id);
        assert_eq!(p.tag, tag);

        let text = format!("lianxi {tok} jieshu MTKN-G7-bad");
        let found = scan(&text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, text.find("MTKN-G7").unwrap());
    }

    #[test]
    fn rejects_adjacent_noise() {
        let id = [3u8; 16];
        let tag = [9u8; 8];
        let tok = build(1, &id, &tag);
        assert!(scan(&format!("x{tok}")).is_empty());
        assert!(scan(&format!("{tok}x")).is_empty());
        assert_eq!(scan(&format!("({tok})")).len(), 1);
    }
}

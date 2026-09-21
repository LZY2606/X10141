//! 识别与裁决引擎：收集所有规则命中，按“显式优先级 -> 最长匹配 -> 位置/登记序”
//! 稳定裁决，并解释每个被压下的命中。已生成的 token 片段受保护，
//! 保证替换后的文本再次处理保持不变（幂等）。

use std::sync::OnceLock;

use rand::RngCore;
use regex::Regex;
use serde::Serialize;

use crate::crypto::{hex_encode, hmac_sha256};
use crate::model::Rule;

const TOKEN_TAG_MAX: usize = 24;

fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[\[TKN:[A-Za-z0-9_\-]{1,24}:[0-9a-f]{32}\]\]").unwrap())
}

/// 规则名净化为 token 中可安全嵌入的标签。
pub fn token_tag(name: &str) -> String {
    let mut tag: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    tag.truncate(TOKEN_TAG_MAX);
    if tag.is_empty() {
        tag.push_str("rule");
    }
    tag
}

/// 由租户密钥单向推导 token。输入包含规则名与版本，
/// 因此“同租户 + 同规则版本 + 同原文”得到稳定 token；
/// 不同租户密钥不同，token 天然不可关联。
pub fn token_for(
    tenant_key: &[u8; 32],
    rule_name: &str,
    rule_version: u64,
    original: &str,
    salt: Option<&[u8]>,
) -> String {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"masking-room/token/v1\0");
    msg.extend_from_slice(rule_name.as_bytes());
    msg.push(0);
    msg.extend_from_slice(rule_version.to_string().as_bytes());
    msg.push(0);
    msg.extend_from_slice(original.as_bytes());
    if let Some(s) = salt {
        msg.push(0);
        msg.extend_from_slice(s);
    }
    let mac = hmac_sha256(tenant_key, &msg);
    format!("[[TKN:{}:{}]]", token_tag(rule_name), hex_encode(&mac[..16]))
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub rule_name: String,
    pub rule_version: u64,
    pub priority: i64,
    pub stable: bool,
    pub start: usize,
    pub end: usize,
    pub matched: String,
    /// "selected" | "suppressed" | "protected"
    pub status: &'static str,
    pub reason: Option<String>,
    pub token: Option<String>,
}

struct Cand<'r> {
    rule: &'r Rule,
    start: usize,
    end: usize,
    matched: String,
}

fn overlaps(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// 对一段文本做全量命中与裁决，返回按文本位置排序的判定列表（不做替换）。
pub fn adjudicate(rules: &[Rule], text: &str) -> Vec<Decision> {
    let protected: Vec<(usize, usize)> = token_regex()
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect();

    let mut cands: Vec<Cand> = Vec::new();
    let mut decisions: Vec<Decision> = Vec::new();

    for rule in rules {
        let re = match Regex::new(&rule.pattern) {
            Ok(r) => r,
            Err(_) => continue, // 登记时已校验，防御性跳过
        };
        for m in re.find_iter(text) {
            if m.start() == m.end() {
                continue; // 忽略零宽命中
            }
            if protected
                .iter()
                .any(|&(s, e)| overlaps(m.start(), m.end(), s, e))
            {
                decisions.push(Decision {
                    rule_name: rule.name.clone(),
                    rule_version: rule.version,
                    priority: rule.priority,
                    stable: rule.stable,
                    start: m.start(),
                    end: m.end(),
                    matched: m.as_str().to_string(),
                    status: "protected",
                    reason: Some("命中与已生成的 token 重叠，跳过以避免二次脱敏".to_string()),
                    token: None,
                });
            } else {
                cands.push(Cand {
                    rule,
                    start: m.start(),
                    end: m.end(),
                    matched: m.as_str().to_string(),
                });
            }
        }
    }

    // 稳定排序：优先级高者先，平级最长匹配先，再按位置与登记序保证确定性。
    let mut order: Vec<usize> = (0..cands.len()).collect();
    order.sort_by(|&a, &b| {
        let (x, y) = (&cands[a], &cands[b]);
        y.rule
            .priority
            .cmp(&x.rule.priority)
            .then((y.end - y.start).cmp(&(x.end - x.start)))
            .then(x.start.cmp(&y.start))
            .then(x.end.cmp(&y.end))
            .then(x.rule.id.cmp(&y.rule.id))
    });

    let mut selected: Vec<usize> = Vec::new();
    for &i in &order {
        let c = &cands[i];
        let winner = selected.iter().copied().find(|&j| {
            let w = &cands[j];
            overlaps(c.start, c.end, w.start, w.end)
        });
        match winner {
            None => {
                selected.push(i);
                decisions.push(Decision {
                    rule_name: c.rule.name.clone(),
                    rule_version: c.rule.version,
                    priority: c.rule.priority,
                    stable: c.rule.stable,
                    start: c.start,
                    end: c.end,
                    matched: c.matched.clone(),
                    status: "selected",
                    reason: None,
                    token: None,
                });
            }
            Some(j) => {
                let w = &cands[j];
                let cause = if w.rule.priority > c.rule.priority {
                    "对方优先级更高".to_string()
                } else if (w.end - w.start) > (c.end - c.start) {
                    "优先级相同，对方命中更长".to_string()
                } else {
                    "优先级与长度相同，对方位置更靠前".to_string()
                };
                decisions.push(Decision {
                    rule_name: c.rule.name.clone(),
                    rule_version: c.rule.version,
                    priority: c.rule.priority,
                    stable: c.rule.stable,
                    start: c.start,
                    end: c.end,
                    matched: c.matched.clone(),
                    status: "suppressed",
                    reason: Some(format!(
                        "被规则「{}」v{} 的命中 [{}..{}] 压下：{}",
                        w.rule.name, w.rule.version, w.start, w.end, cause
                    )),
                    token: None,
                });
            }
        }
    }

    decisions.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(a.end.cmp(&b.end))
            .then(a.rule_name.cmp(&b.rule_name))
    });
    decisions
}

/// 执行脱敏：对裁决为 selected 的片段生成 token 并替换。
/// 返回（脱敏后文本， 带 token 的判定列表）。
pub fn redact(text: &str, rules: &[Rule], tenant_key: &[u8; 32]) -> (String, Vec<Decision>) {
    let mut decisions = adjudicate(rules, text);
    let mut sel_idx: Vec<usize> = decisions
        .iter()
        .enumerate()
        .filter(|(_, d)| d.status == "selected")
        .map(|(i, _)| i)
        .collect();
    sel_idx.sort_by_key(|&i| decisions[i].start);

    let mut out = String::with_capacity(text.len());
    let mut pos = 0usize;
    for i in sel_idx {
        let d = &decisions[i];
        out.push_str(&text[pos..d.start]);
        let salt = if d.stable {
            None
        } else {
            let mut s = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut s);
            Some(s)
        };
        let token = token_for(
            tenant_key,
            &d.rule_name,
            d.rule_version,
            &d.matched,
            salt.as_ref().map(|s| s.as_slice()),
        );
        out.push_str(&token);
        pos = d.end;
        decisions[i].token = Some(token);
    }
    out.push_str(&text[pos..]);
    (out, decisions)
}

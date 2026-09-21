use regex::Regex;

use crate::state::{MatchKind, Rule};

pub const TOKEN_PREFIX: &str = "⟦TKN-";
pub const TOKEN_SUFFIX: &str = "⟧";

pub fn token_regex() -> Regex {
    Regex::new(r"⟦TKN-[A-Za-z0-9_\-]{22}⟧").expect("token regex compiles")
}

pub fn make_token(token_id: &str) -> String {
    format!("{TOKEN_PREFIX}{token_id}{TOKEN_SUFFIX}")
}

/// 接受完整 token（⟦TKN-…⟧）或裸 token id。
pub fn extract_token_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let inner = trimmed
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|s| s.strip_suffix(TOKEN_SUFFIX))
        .unwrap_or(trimmed);
    if inner.len() == 22 && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Some(inner.to_string())
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub rule_idx: usize,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

impl Candidate {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

pub fn find_candidates(rules: &[Rule], text: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        match rule.kind {
            MatchKind::Literal => {
                if rule.pattern.is_empty() {
                    continue;
                }
                for (start, m) in text.match_indices(&rule.pattern) {
                    out.push(Candidate { rule_idx: i, start, end: start + m.len(), matched: m.to_string() });
                }
            }
            MatchKind::Regex => {
                if let Ok(re) = Regex::new(&rule.pattern) {
                    for m in re.find_iter(text) {
                        if m.start() == m.end() {
                            continue;
                        }
                        out.push(Candidate {
                            rule_idx: i,
                            start: m.start(),
                            end: m.end(),
                            matched: m.as_str().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
pub struct Suppressed {
    pub cand: Candidate,
    pub by: Candidate,
}

#[derive(Clone, Debug, Default)]
pub struct Adjudication {
    pub accepted: Vec<Candidate>,
    pub suppressed: Vec<Suppressed>,
}

fn overlaps(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// 稳定裁决：优先级降序 -> 最长匹配 -> 起始位置升序 -> 规则 id 升序。
/// 与已接受命中重叠的候选被压下，并记录压下者。
pub fn adjudicate(rules: &[Rule], candidates: Vec<Candidate>, protected: &[(usize, usize)]) -> Adjudication {
    let mut cands: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| !protected.iter().any(|&(ps, pe)| overlaps(c.start, c.end, ps, pe)))
        .collect();
    cands.sort_by(|a, b| {
        let ra = &rules[a.rule_idx];
        let rb = &rules[b.rule_idx];
        rb.priority
            .cmp(&ra.priority)
            .then(b.len().cmp(&a.len()))
            .then(a.start.cmp(&b.start))
            .then(ra.id.cmp(&rb.id))
    });
    let mut accepted: Vec<Candidate> = Vec::new();
    let mut suppressed: Vec<Suppressed> = Vec::new();
    for cand in cands {
        if let Some(winner) = accepted.iter().find(|w| overlaps(cand.start, cand.end, w.start, w.end)) {
            suppressed.push(Suppressed { by: winner.clone(), cand });
        } else {
            accepted.push(cand);
        }
    }
    accepted.sort_by_key(|c| c.start);
    Adjudication { accepted, suppressed }
}

/// 已脱敏文本中的 token 区间受保护，避免 token 自身被再次识别（幂等）。
pub fn protected_spans(text: &str) -> Vec<(usize, usize)> {
    token_regex().find_iter(text).map(|m| (m.start(), m.end())).collect()
}

//! 领域模型：规则、命中、裁决结果与统一错误。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleKind {
    /// 内置：电子邮箱。
    Email,
    /// 内置：18 位中国居民身份证号（校验位必须通过）。
    IdCard,
    /// 自定义：正则表达式。
    Regex { pattern: String },
    /// 自定义：整数范围（按连续数字串识别，闭区间）。
    Range { min: i128, max: i128 },
}

impl RuleKind {
    pub fn kind_name(&self) -> &'static str {
        match self {
            RuleKind::Email => "email",
            RuleKind::IdCard => "idcard",
            RuleKind::Regex { .. } => "regex",
            RuleKind::Range { .. } => "range",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: RuleKind,
    /// 数值越大优先级越高。
    pub priority: i32,
    /// true：同租户+同规则版本+同原文稳定复用；false：每次随机 token。
    pub stable: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub rule_id: String,
    pub rule_name: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub priority: i32,
    pub stable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suppressed {
    pub rule_id: String,
    pub rule_name: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub reason: String,
    /// 压下它的胜出命中。
    pub by_rule_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Adjudication {
    pub accepted: Vec<Hit>,
    pub suppressed: Vec<Suppressed>,
}

#[derive(Debug)]
pub enum EngineError {
    BadInput(String),
    NotFound(String),
    /// 所有 token 无效情形统一错误（格式错、签名错、租户不匹配、映射缺失）。
    InvalidToken,
    Conflict(String),
    Corrupt(String),
    Io(String),
}

impl EngineError {
    pub fn http_status(&self) -> u16 {
        match self {
            EngineError::BadInput(_) => 400,
            EngineError::NotFound(_) => 404,
            EngineError::InvalidToken => 422,
            EngineError::Conflict(_) => 409,
            EngineError::Corrupt(_) => 500,
            EngineError::Io(_) => 500,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            EngineError::BadInput(_) => "bad_input",
            EngineError::NotFound(_) => "not_found",
            EngineError::InvalidToken => "invalid_token",
            EngineError::Conflict(_) => "conflict",
            EngineError::Corrupt(_) => "corrupt_state",
            EngineError::Io(_) => "io_error",
        }
    }

    pub fn message(&self) -> String {
        match self {
            // 故意不回显任何与 token/租户相关的细节。
            EngineError::InvalidToken => "token 无效、已失效或不属于当前租户".to_string(),
            EngineError::BadInput(m) => m.clone(),
            EngineError::NotFound(m) => m.clone(),
            EngineError::Conflict(m) => m.clone(),
            EngineError::Corrupt(m) => format!("本地状态损坏：{m}"),
            EngineError::Io(m) => format!("本地读写失败：{m}"),
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for EngineError {}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Io(e.to_string())
    }
}

pub type EngineResult<T> = Result<T, EngineError>;

fn email_re() -> &'static Regex {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    EMAIL.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}").unwrap())
}

fn idcard_re() -> &'static Regex {
    static ID: OnceLock<Regex> = OnceLock::new();
    ID.get_or_init(|| Regex::new(r"[1-9][0-9]{16}[0-9Xx]").unwrap())
}

fn custom_re(pattern: &str) -> EngineResult<Regex> {
    Regex::new(pattern).map_err(|e| EngineError::BadInput(format!("正则表达式非法：{e}")))
}

pub fn validate_rule(kind: &RuleKind) -> EngineResult<()> {
    match kind {
        RuleKind::Range { min, max } => {
            if min > max {
                return Err(EngineError::BadInput("范围规则要求 min <= max".into()));
            }
            Ok(())
        }
        RuleKind::Regex { pattern } => custom_re(pattern).map(|_| ()),
        _ => Ok(()),
    }
}

/// 身份证校验位（GB 11643-1999 加权因子法）。
fn idcard_checksum_ok(num: &str) -> bool {
    if num.len() != 18 {
        return false;
    }
    let weights = [7u32, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let check = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let bytes = num.as_bytes();
    let mut sum = 0u32;
    for i in 0..17 {
        sum += (bytes[i] - b'0') as u32 * weights[i];
    }
    let last = bytes[17].to_ascii_uppercase() as char;
    check[(sum % 11) as usize] == last
}

/// 单条规则在文本上的全部命中（字节偏移，UTF-8 安全）。
pub fn find_hits(rule: &Rule, text: &str) -> EngineResult<Vec<Hit>> {
    if !rule.enabled {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let push = |out: &mut Vec<Hit>, m: regex::Match<'_>| {
        let s = m.start();
        let e = m.end();
        if s == e {
            return;
        }
        out.push(Hit {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            start: s,
            end: e,
            text: text[s..e].to_string(),
            priority: rule.priority,
            stable: rule.stable,
        });
    };
    match &rule.kind {
        RuleKind::Email => {
            for m in email_re().find_iter(text) {
                // 避免吃到紧邻的字母数字（边界保护）。
                let before_ok = m.start() == 0
                    || !text.as_bytes()[m.start() - 1].is_ascii_alphanumeric();
                let after_ok = m.end() == text.len()
                    || !text.as_bytes()[m.end()].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    push(&mut out, m);
                }
            }
        }
        RuleKind::IdCard => {
            for m in idcard_re().find_iter(text) {
                let before_ok = m.start() == 0
                    || !text.as_bytes()[m.start() - 1].is_ascii_alphanumeric();
                let after_ok = m.end() == text.len()
                    || !text.as_bytes()[m.end()].is_ascii_alphanumeric();
                if before_ok && after_ok && idcard_checksum_ok(&text[m.start()..m.end()]) {
                    push(&mut out, m);
                }
            }
        }
        RuleKind::Regex { pattern } => {
            let re = custom_re(pattern)?;
            for m in re.find_iter(text) {
                push(&mut out, m);
            }
        }
        RuleKind::Range { min, max } => {
            let bytes = text.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i].is_ascii_digit() {
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    let end = i;
                    // 限制长度，防止溢出；超过 i128 范围的数字串不视为编号。
                    if end - start <= 38 {
                        if let Ok(v) = text[start..end].parse::<u128>() {
                            if v <= i128::MAX as u128 {
                                let v = v as i128;
                                if v >= *min && v <= *max {
                                    out.push(Hit {
                                        rule_id: rule.id.clone(),
                                        rule_name: rule.name.clone(),
                                        start,
                                        end,
                                        text: text[start..end].to_string(),
                                        priority: rule.priority,
                                        stable: rule.stable,
                                    });
                                }
                            }
                        }
                    }
                } else {
                    i += 1;
                }
            }
        }
    }
    Ok(out)
}

fn overlaps(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// 显式优先级 + 最长匹配的稳定裁决。
/// `protected` 为不允许再识别的区间（已存在 token），直接压下重叠命中。
pub fn adjudicate(mut hits: Vec<Hit>, protected: &[(usize, usize)]) -> Adjudication {
    // 排序键：优先级↓、长度↓、起点↑、规则 ID↑（字典序）。
    hits.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
            .then(a.rule_id.cmp(&b.rule_id))
    });

    let mut accepted: Vec<Hit> = Vec::new();
    let mut suppressed: Vec<Suppressed> = Vec::new();

    for hit in hits {
        if let Some(p) = protected
            .iter()
            .find(|(ps, pe)| overlaps(hit.start, hit.end, *ps, *pe))
        {
            suppressed.push(Suppressed {
                rule_id: hit.rule_id.clone(),
                rule_name: hit.rule_name.clone(),
                start: hit.start,
                end: hit.end,
                text: hit.text.clone(),
                reason: "inside-existing-token".to_string(),
                by_rule_id: format!("token@{}..{}", p.0, p.1),
            });
            continue;
        }
        if let Some(winner) = accepted
            .iter()
            .find(|w| overlaps(hit.start, hit.end, w.start, w.end))
        {
            let reason = if winner.priority > hit.priority {
                "overlap-higher-priority"
            } else if winner.end - winner.start > hit.end - hit.start {
                "overlap-longer-match"
            } else {
                "overlap-stable-tiebreak"
            };
            suppressed.push(Suppressed {
                rule_id: hit.rule_id.clone(),
                rule_name: hit.rule_name.clone(),
                start: hit.start,
                end: hit.end,
                text: hit.text.clone(),
                reason: reason.to_string(),
                by_rule_id: winner.rule_id.clone(),
            });
        } else {
            accepted.push(hit);
        }
    }

    accepted.sort_by_key(|h| (h.start, h.rule_id.clone()));
    suppressed.sort_by_key(|s| (s.start, s.rule_id.clone()));
    Adjudication { accepted, suppressed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, kind: RuleKind, prio: i32, stable: bool) -> Rule {
        Rule {
            id: id.into(),
            name: id.into(),
            kind,
            priority: prio,
            stable,
            enabled: true,
        }
    }

    #[test]
    fn idcard_checksum() {
        // 公开示例号（校验位正确，非真实号码段）。
        let r = rule("id", RuleKind::IdCard, 1, false);
        let hits = find_hits(&r, "号 11010519491231002X 结束").unwrap();
        assert_eq!(hits.len(), 1);
        let r2 = find_hits(&rule("id2", RuleKind::IdCard, 1, false), "110105194912310020").unwrap();
        assert!(r2.is_empty());
    }

    #[test]
    fn priority_and_longest() {
        let email = rule("mail", RuleKind::Email, 10, false);
        let custom = rule(
            "all",
            RuleKind::Regex { pattern: r"[A-Za-z0-9@.]+".into() },
            1,
            false,
        );
        let text = "lianxi a@b.com end";
        let mut hits = find_hits(&email, text).unwrap();
        hits.extend(find_hits(&custom, text).unwrap());
        let adj = adjudicate(hits, &[]);
        // 不与邮箱重叠的两段普通单词照常保留；只有与邮箱重叠的同段被压下。
        assert!(adj.accepted.iter().any(|h| h.rule_id == "mail"));
        assert!(adj.accepted.iter().filter(|h| h.rule_id == "all").count() == 2);
        let sup = adj.suppressed.iter().find(|s| s.rule_id == "all").unwrap();
        assert_eq!(sup.reason, "overlap-higher-priority");
        assert_eq!(sup.by_rule_id, "mail");
    }
}

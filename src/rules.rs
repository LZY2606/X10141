//! 规则模型、片段识别（含 token 保护区）与显式优先级 + 最长匹配裁决。

use crate::engine::{self, Program};
use crate::error::{Error, Result};
use std::collections::HashMap;

pub const KIND_EMAIL: &str = "email";
pub const KIND_NUMBER: &str = "number";
pub const KIND_PATTERN: &str = "pattern";
pub const KIND_RANGE: &str = "range";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub pattern: String,
    pub priority: i32,
    pub enabled: bool,
}

impl Rule {
    pub fn metadata(&self) -> Vec<(String, crate::json::Value)> {
        use crate::json::Value;
        vec![
            ("id".to_string(), Value::str(&self.id)),
            ("name".to_string(), Value::str(&self.name)),
            ("kind".to_string(), Value::str(&self.kind)),
            ("pattern_preview".to_string(), Value::str(pattern_preview(self))),
            ("priority".to_string(), Value::Num(self.priority.to_string())),
            ("enabled".to_string(), Value::Bool(self.enabled)),
        ]
    }
}

fn pattern_preview(rule: &Rule) -> String {
    if rule.kind == KIND_PATTERN {
        rule.pattern.chars().take(64).collect()
    } else {
        rule.pattern.clone()
    }
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub version: String,
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn validate(&self) -> Result<()> {
        if self.version.trim().is_empty() {
            return Err(Error::invalid("规则版本不能为空"));
        }
        if self.rules.is_empty() {
            return Err(Error::invalid("规则集至少需要一条规则"));
        }
        let mut seen = HashMap::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(Error::invalid("规则 id 不能为空"));
            }
            if seen.insert(rule.id.clone(), ()).is_some() {
                return Err(Error::conflict(format!("规则 id 重复: {}", rule.id)));
            }
            validate_rule(rule)?;
        }
        Ok(())
    }

    pub fn find(&self, rule_id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }
}

pub fn validate_rule(rule: &Rule) -> Result<()> {
    match rule.kind.as_str() {
        KIND_EMAIL | KIND_NUMBER => {
            if !rule.pattern.is_empty() {
                return Err(Error::invalid(format!(
                    "内置规则 {} 不接受自定义 pattern",
                    rule.kind
                )));
            }
        }
        KIND_PATTERN => {
            engine::parse(&rule.pattern).map_err(|e| {
                Error::invalid(format!("规则 {} 的正则无效: {}", rule.id, e))
            })?;
        }
        KIND_RANGE => {}
        other => return Err(Error::invalid(format!("未知规则类型: {}", other))),
    }
    Ok(())
}

/// 请求中临时提供的自定义字符区间（基于 UTF-16 风格的“字符序号”由调用方换算成字节偏移）。
#[derive(Debug, Clone)]
pub struct CustomRange {
    pub rule_id: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub rule_id: String,
}

#[derive(Debug, Clone)]
pub struct Suppressed {
    pub start: usize,
    pub end: usize,
    pub rule_id: String,
    pub by_rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Adjudication {
    pub selected: Vec<Candidate>,
    pub suppressed: Vec<Suppressed>,
}

pub struct CompiledRules {
    by_id: HashMap<String, CompiledRule>,
}

struct CompiledRule {
    rule: Rule,
    program: Option<Program>,
}

pub fn compile_rules(rules: &[Rule]) -> Result<CompiledRules> {
    let mut by_id = HashMap::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let program = match rule.kind.as_str() {
            KIND_EMAIL => Some(compile_pattern(EMAIL_PATTERN)?),
            KIND_NUMBER => Some(compile_pattern(NUMBER_PATTERN)?),
            KIND_PATTERN => Some(compile_pattern(&rule.pattern)?),
            KIND_RANGE => None,
            _ => return Err(Error::invalid(format!("未知规则类型: {}", rule.kind))),
        };
        by_id.insert(
            rule.id.clone(),
            CompiledRule {
                rule: rule.clone(),
                program,
            },
        );
    }
    Ok(CompiledRules { by_id })
}

fn compile_pattern(pattern: &str) -> Result<Program> {
    let expr = engine::parse(pattern)
        .map_err(|e| Error::invalid(format!("内置正则编译失败: {}", e)))?;
    engine::compile(&expr).map_err(|e| Error::invalid(format!("内置正则编译失败: {}", e)))
}

pub const EMAIL_PATTERN: &str = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+";
pub const NUMBER_PATTERN: &str = "[0-9]{4,}";
pub const TOKEN_PATTERN: &str = "TOK\\.[0-9a-v]{24}";

/// 识别所有候选片段；token 形态的文本永远是受保护区，永不命中任何业务规则。
pub fn collect_candidates(
    text: &str,
    rules: &[Rule],
    custom: &[CustomRange],
) -> Result<(Vec<Candidate>, Vec<(usize, usize)>)> {
    let compiled = compile_rules(rules)?;
    let bytes = text.as_bytes();
    let token_program = compile_pattern(TOKEN_PATTERN)?;
    let mut protected: Vec<(usize, usize)> = engine::find_matches(&token_program, text)
        .into_iter()
        .map(|h| {
            let s = h.start;
            let e = h.end;
            // 只有左右边界都不接 base32hex 字符时才认定为 token，避免切断更长的串。
            (s, e)
        })
        .filter(|(s, e)| {
            let left_ok = *s == 0
                || bytes
                    .get(s - 1)
                    .map_or(true, |b| !is_b32hex_byte(*b) && *b != b'.');
            let right_ok = *e == bytes.len() || bytes.get(*e).map_or(true, |b| !is_b32hex_byte(*b));
            left_ok && right_ok
        })
        .collect();
    protected.sort_by_key(|(s, e)| (*s, *e));

    let mut candidates: Vec<Candidate> = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if rule.kind == KIND_RANGE {
            continue;
        }
        let cr = match compiled.by_id.get(&rule.id) {
            Some(cr) => cr,
            None => continue,
        };
        if let Some(program) = &cr.program {
            for hit in engine::find_matches(program, text) {
                if overlaps_any(hit.start, hit.end, &protected) {
                    continue;
                }
                candidates.push(Candidate {
                    start: hit.start,
                    end: hit.end,
                    rule_id: rule.id.clone(),
                });
            }
        }
    }
    for range in custom {
        if range.start >= range.end || range.end > bytes.len() {
            return Err(Error::invalid(format!(
                "自定义区间非法: [{}, {})",
                range.start, range.end
            )));
        }
        if !text.is_char_boundary(range.start) || !text.is_char_boundary(range.end) {
            return Err(Error::invalid("自定义区间必须落在字符边界上"));
        }
        if overlaps_any(range.start, range.end, &protected) {
            continue;
        }
        candidates.push(Candidate {
            start: range.start,
            end: range.end,
            rule_id: range.rule_id.clone(),
        });
    }
    Ok((candidates, protected))
}

fn overlaps_any(start: usize, end: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|(s, e)| start < *e && *s < end)
}

fn is_b32hex_byte(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'v').contains(&b) || (b'A'..=b'V').contains(&b)
}

/// 显式优先级降序、同优先级最长匹配优先，再以起点、规则 id 稳定裁决。
pub fn adjudicate(
    mut candidates: Vec<Candidate>,
    rule_priority: impl Fn(&str) -> Option<i32>,
) -> Adjudication {
    candidates.sort_by(|a, b| {
        let pa = rule_priority(&a.rule_id).unwrap_or(i32::MIN);
        let pb = rule_priority(&b.rule_id).unwrap_or(i32::MIN);
        pb.cmp(&pa)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.end.cmp(&b.end))
    });

    let mut selected: Vec<Candidate> = Vec::new();
    let mut suppressed: Vec<Suppressed> = Vec::new();
    for cand in candidates {
        if let Some(winner) = selected
            .iter()
            .find(|s| cand.start < s.end && s.start < cand.end)
        {
            let winner_priority = rule_priority(&winner.rule_id).unwrap_or(i32::MIN);
            let cand_priority = rule_priority(&cand.rule_id).unwrap_or(i32::MIN);
            let reason = if winner_priority > cand_priority {
                "lower_priority"
            } else if winner_priority == cand_priority
                && (winner.end - winner.start) > (cand.end - cand.start)
            {
                "shorter_match"
            } else if winner_priority == cand_priority
                && (winner.end - winner.start) == (cand.end - cand.start)
            {
                "stable_order_tie_break"
            } else {
                "overlap"
            };
            suppressed.push(Suppressed {
                start: cand.start,
                end: cand.end,
                rule_id: cand.rule_id,
                by_rule_id: winner.rule_id.clone(),
                reason: reason.to_string(),
            });
        } else {
            selected.push(cand);
        }
    }
    selected.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
    suppressed.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
    Adjudication {
        selected,
        suppressed,
    }
}

/// 将裁决结果应用到文本：从右向左替换，避免偏移失效。
pub fn apply_selected(
    text: &str,
    selected: &[Candidate],
    mut token_for: impl FnMut(usize) -> String,
) -> String {
    let mut ordered: Vec<(usize, usize, String)> = selected
        .iter()
        .enumerate()
        .map(|(i, c)| (c.start, c.end, token_for(i)))
        .collect();
    ordered.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = text.to_string();
    for (start, end, token) in ordered {

        out.replace_range(start..end, &token);
    }
    out
}

pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "email".into(),
            name: "邮箱".into(),
            kind: KIND_EMAIL.into(),
            pattern: String::new(),
            priority: 100,
            enabled: true,
        },
        Rule {
            id: "number".into(),
            name: "数字编号".into(),
            kind: KIND_NUMBER.into(),
            pattern: String::new(),
            priority: 10,
            enabled: true,
        },
    ]
}

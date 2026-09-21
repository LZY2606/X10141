//! 轻量正则引擎：解析为 AST，编译为线性字节码，回溯执行。
//! 仅支持脱敏规则所需子集（字符类、量词、分组、锚点、交替）。

use std::char;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pred {
    Any,
    Class { negated: bool, ranges: Vec<(char, char)> },
    Literal(char),
}

impl Pred {
    fn matches(&self, c: char) -> bool {
        match self {
            Pred::Any => c != '\n',
            Pred::Literal(l) => c == *l,
            Pred::Class { negated, ranges } => {
                let inside = ranges.iter().any(|(lo, hi)| c >= *lo && c <= *hi);
                inside != *negated
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Char(Pred),
    Start,
    End,
    Concat(Vec<Expr>),
    Alt(Vec<Expr>),
    Repeat {
        atom: Box<Expr>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
}

const MAX_REPEAT: u32 = 64;

pub fn parse(pattern: &str) -> Result<Expr, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut p = Parser { chars, pos: 0 };
    let expr = p.parse_alternation()?;
    if p.pos != p.chars.len() {
        return Err(format!("unexpected '{}' at {}", p.chars[p.pos], p.pos));
    }
    Ok(expr)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn parse_alternation(&mut self) -> Result<Expr, String> {
        let first = self.parse_concat()?;
        let mut alts = vec![first];
        while self.peek() == Some('|') {
            self.pos += 1;
            alts.push(self.parse_concat()?);
        }
        if alts.len() == 1 {
            Ok(alts.pop().unwrap())
        } else {
            Ok(Expr::Alt(alts))
        }
    }

    fn parse_concat(&mut self) -> Result<Expr, String> {
        let mut parts = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            parts.push(self.parse_repeat()?);
        }
        if parts.is_empty() {
            Ok(Expr::Concat(Vec::new()))
        } else if parts.len() == 1 {
            Ok(parts.pop().unwrap())
        } else {
            Ok(Expr::Concat(parts))
        }
    }

    fn parse_repeat(&mut self) -> Result<Expr, String> {
        let mut atom = self.parse_atom()?;
        while let Some(c) = self.peek() {
            match c {
                '*' | '+' | '?' => {
                    self.pos += 1;
                    let (min, max) = match c {
                        '*' => (0, None),
                        '+' => (1, None),
                        _ => (0, Some(1)),
                    };
                    let greedy = self.parse_greediness();
                    atom = Expr::Repeat {
                        atom: Box::new(atom),
                        min,
                        max,
                        greedy,
                    };
                }
                '{' => {
                    if let Some((min, max)) = self.try_parse_braces()? {
                        let greedy = self.parse_greediness();
                        atom = Expr::Repeat {
                            atom: Box::new(atom),
                            min,
                            max,
                            greedy,
                        };
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(atom)
    }

    fn parse_greediness(&mut self) -> bool {
        if self.peek() == Some('?') {
            self.pos += 1;
            false
        } else {
            true
        }
    }

    fn try_parse_braces(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
        let save = self.pos;
        self.pos += 1;
        let mut min_str = String::new();
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            min_str.push(self.chars[self.pos]);
            self.pos += 1;
        }
        let min: u32 = match min_str.parse() {
            Ok(v) => v,
            Err(_) => {
                self.pos = save;
                return Ok(None);
            }
        };
        let max = if self.peek() == Some(',') {
            self.pos += 1;
            let mut max_str = String::new();
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                max_str.push(self.chars[self.pos]);
                self.pos += 1;
            }
            if max_str.is_empty() {
                None
            } else {
                let v: u32 = max_str.parse().map_err(|_| "bad repeat".to_string())?;
                Some(v)
            }
        } else {
            Some(min)
        };
        if self.peek() != Some('}') {
            self.pos = save;
            return Ok(None);
        }
        self.pos += 1;
        if min > MAX_REPEAT || max.map_or(false, |m| m > MAX_REPEAT) {
            return Err(format!("repeat bound exceeds {}", MAX_REPEAT));
        }
        if let Some(m) = max {
            if m < min {
                return Err("repeat max < min".into());
            }
        }
        Ok(Some((min, max)))
    }

    fn parse_atom(&mut self) -> Result<Expr, String> {
        let c = self.peek().ok_or_else(|| "unexpected end of pattern".to_string())?;
        match c {
            '(' => {
                self.pos += 1;
                if self.peek() == Some('?') {
                    return Err("lookaround/groups flags are not supported".into());
                }
                let inner = self.parse_alternation()?;
                if self.peek() != Some(')') {
                    return Err("missing closing ')'".into());
                }
                self.pos += 1;
                Ok(inner)
            }
            '[' => self.parse_class(),
            '.' => {
                self.pos += 1;
                Ok(Expr::Char(Pred::Any))
            }
            '^' => {
                self.pos += 1;
                Ok(Expr::Start)
            }
            '$' => {
                self.pos += 1;
                Ok(Expr::End)
            }
            '\\' => {
                self.pos += 1;
                let e = self
                    .peek()
                    .ok_or_else(|| "dangling escape".to_string())?;
                self.pos += 1;
                Ok(escape_expr(e))
            }
            ')' | '|' | '*' | '+' | '?' => {
                Err(format!("unexpected '{}' at {}", c, self.pos))
            }
            other => {
                self.pos += 1;
                Ok(Expr::Char(Pred::Literal(other)))
            }
        }
    }

    fn parse_class(&mut self) -> Result<Expr, String> {
        self.pos += 1;
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut ranges: Vec<(char, char)> = Vec::new();
        let mut first = true;
        loop {
            let c = match self.peek() {
                Some(']') if !first => {
                    self.pos += 1;
                    break;
                }
                Some(c) => c,
                None => return Err("unterminated character class".into()),
            };
            first = false;
            let lo = if c == '\\' {
                self.pos += 1;
                let e = self
                    .peek()
                    .ok_or_else(|| "dangling escape in class".to_string())?;
                self.pos += 1;
                class_escape(e)?
            } else {
                self.pos += 1;
                c
            };
            if self.peek() == Some('-')
                && self
                    .chars
                    .get(self.pos + 1)
                    .map_or(false, |&n| n != ']')
            {
                self.pos += 1;
                let hi = if self.peek() == Some('\\') {
                    self.pos += 1;
                    let e = self
                        .peek()
                        .ok_or_else(|| "dangling escape in class".to_string())?;
                    self.pos += 1;
                    class_escape(e)?
                } else {
                    let h = self.peek().ok_or_else(|| "bad range".to_string())?;
                    self.pos += 1;
                    h
                };
                if hi < lo {
                    return Err("character range reversed".into());
                }
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        Ok(Expr::Char(Pred::Class { negated, ranges }))
    }
}

fn class_escape(c: char) -> Result<char, String> {
    match c {
        'n' => Ok('\n'),
        'r' => Ok('\r'),
        't' => Ok('\t'),
        'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
            Err("shorthand classes not supported inside explicit classes; list the ranges".into())
        }
        other => Ok(other),
    }
}

fn escape_expr(c: char) -> Expr {
    match c {
        'd' => Expr::Char(Pred::Class {
            negated: false,
            ranges: vec![('0', '9')],
        }),
        'D' => Expr::Char(Pred::Class {
            negated: true,
            ranges: vec![('0', '9')],
        }),
        'w' => Expr::Char(Pred::Class {
            negated: false,
            ranges: vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
        }),
        'W' => Expr::Char(Pred::Class {
            negated: true,
            ranges: vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
        }),
        's' => Expr::Char(Pred::Class {
            negated: false,
            ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')],
        }),
        'S' => Expr::Char(Pred::Class {
            negated: true,
            ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')],
        }),
        'n' => Expr::Char(Pred::Literal('\n')),
        'r' => Expr::Char(Pred::Literal('\r')),
        't' => Expr::Char(Pred::Literal('\t')),
        other => Expr::Char(Pred::Literal(other)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Char(Pred),
    Start,
    End,
    Jump(usize),
    Split(usize, usize),
    Match,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub ops: Vec<Op>,
}

pub fn compile(expr: &Expr) -> Result<Program, String> {
    let mut ops: Vec<Op> = Vec::new();
    compile_expr(expr, &mut ops)?;
    ops.push(Op::Match);
    Ok(Program { ops })
}

fn compile_expr(expr: &Expr, ops: &mut Vec<Op>) -> Result<(), String> {
    match expr {
        Expr::Char(p) => ops.push(Op::Char(p.clone())),
        Expr::Start => ops.push(Op::Start),
        Expr::End => ops.push(Op::End),
        Expr::Concat(parts) => {
            for p in parts {
                compile_expr(p, ops)?;
            }
        }
        Expr::Alt(alts) => {
            let mut jump_placeholders = Vec::new();
            for (i, alt) in alts.iter().enumerate() {
                if i + 1 < alts.len() {
                    ops.push(Op::Split(usize::MAX, usize::MAX));
                    let split_idx = ops.len() - 1;
                    let body_start = ops.len();
                    compile_expr(alt, ops)?;
                    let jump_idx = ops.len();
                    jump_placeholders.push(jump_idx);
                    ops.push(Op::Jump(usize::MAX));
                    let next_start = ops.len();
                    ops[split_idx] = Op::Split(body_start, next_start);
                } else {
                    compile_expr(alt, ops)?;
                }
            }
            let end = ops.len();
            for j in jump_placeholders {
                ops[j] = Op::Jump(end);
            }
        }
        Expr::Repeat {
            atom,
            min,
            max,
            greedy,
        } => {
            for _ in 0..*min {
                compile_expr(atom, ops)?;
            }
            match max {
                Some(m) => {
                    let optional = *m - *min;
                    let mut split_indices = Vec::new();
                    for _ in 0..optional {
                        split_indices.push(ops.len());
                        ops.push(Op::Split(usize::MAX, usize::MAX));
                        compile_expr(atom, ops)?;
                    }
                    let end = ops.len();
                    for (i, &split_idx) in split_indices.iter().enumerate() {
                        let body = split_idx + 1;
                        let next = if i + 1 < split_indices.len() {
                            split_indices[i + 1]
                        } else {
                            end
                        };
                        // 回溯栈先压第二分支，因此第一分支优先尝试。
                        ops[split_idx] = if *greedy {
                            Op::Split(body, next)
                        } else {
                            Op::Split(next, body)
                        };
                    }
                }
                None => {
                    let split_idx = ops.len();
                    ops.push(Op::Split(usize::MAX, usize::MAX));
                    let body_start = ops.len();
                    compile_expr(atom, ops)?;
                    ops.push(Op::Jump(split_idx));
                    let after = ops.len();
                    if *greedy {
                        ops[split_idx] = Op::Split(body_start, after);
                    } else {
                        ops[split_idx] = Op::Split(after, body_start);
                    }
                }
            }
        }
    }
    Ok(())
}

impl Program {
    /// 从 `chars[start..]` 尝试匹配，返回匹配结束的字节偏移（不含）；不匹配返回 None。
    pub fn matches_at(&self, text: &str, byte_start: usize) -> Option<usize> {
        let bytes = text.as_bytes();
        let mut threads: Vec<(usize, usize)> = Vec::new();
        threads.push((0, byte_start));
        let mut steps = 0u64;
        const STEP_CAP: u64 = 2_000_000;
        let mut best: Option<usize> = None;
        while let Some((pc, pos)) = threads.pop() {
            steps += 1;
            if steps > STEP_CAP {
                return None;
            }
            match &self.ops[pc] {
                Op::Char(pred) => {
                    if pos >= bytes.len() {
                        continue;
                    }
                    let ch = next_char(bytes, pos)?;
                    if pred.matches(ch) {
                        let npos = pos + ch.len_utf8();
                        threads.push((pc + 1, npos));
                    }
                }
                Op::Start => {
                    if pos == 0 {
                        threads.push((pc + 1, pos));
                    }
                }
                Op::End => {
                    if pos == bytes.len() {
                        threads.push((pc + 1, pos));
                    }
                }
                Op::Jump(t) => threads.push((*t, pos)),
                Op::Split(a, b) => {
                    threads.push((*b, pos));
                    threads.push((*a, pos));
                }
                Op::Match => {
                    best = Some(match best {
                        Some(prev) if prev > pos => prev,
                        _ => pos,
                    });
                }
            }
        }
        best
    }
}

fn next_char(bytes: &[u8], pos: usize) -> Option<char> {
    let width = match bytes[pos] {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        b if b >> 3 == 0b11110 => 4,
        _ => return None,
    };
    let slice = bytes.get(pos..pos + width)?;
    std::str::from_utf8(slice).ok().and_then(|s| s.chars().next())
}

#[derive(Debug, Clone, Copy)]
pub struct RawHit {
    pub start: usize,
    pub end: usize,
}

/// 左起非重叠扫描；空匹配后前进一个字节。
pub fn find_matches(program: &Program, text: &str) -> Vec<RawHit> {
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    let mut pos = 0usize;
    while pos <= bytes.len() {
        if let Some(end) = program.matches_at(text, pos) {
            if end == pos {
                if pos == bytes.len() {
                    break;
                }
                pos += 1;
            } else {
                hits.push(RawHit { start: pos, end });
                pos = end;
            }
        } else if pos < bytes.len() {
            pos += bytes[pos].len_utf8().max(1);
        } else {
            break;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(pattern: &str, text: &str) -> Vec<(usize, usize)> {
        let e = parse(pattern).unwrap();
        let p = compile(&e).unwrap();
        find_matches(&p, text)
            .into_iter()
            .map(|h| (h.start, h.end))
            .collect()
    }

    #[test]
    fn literal_and_class() {
        assert_eq!(hits("abc", "zabcabc"), vec![(1, 4), (4, 7)]);
        assert_eq!(hits("[0-9]+", "a12b99"), vec![(1, 3), (4, 6)]);
        assert_eq!(hits("ab?c", "ac abc"), vec![(0, 2), (3, 6)]);
        assert_eq!(hits("a|ab", "ab"), vec![(0, 1)]);
    }

    #[test]
    fn email_pattern() {
        let pat = "[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+";
        let got = hits(pat, "contact a.b@example.com later");
        assert_eq!(got, vec![(8, 25)]);
    }

    #[test]
    fn greedy_vs_lazy() {
        assert_eq!(hits("a.*a", "axa"), vec![(0, 3)]);
        assert_eq!(hits("a.*?a", "axa"), vec![(0, 3)]);
        assert_eq!(hits("a.*?b", "abab"), vec![(0, 2)]);
    }

    #[test]
    fn anchors_and_repeats() {
        let e = parse("^a{1,2}$").unwrap();
        let p = compile(&e).unwrap();
        assert_eq!(p.matches_at("aa", 0), Some(2));
        assert_eq!(p.matches_at("aaa", 0), None);
    }

    #[test]
    fn empty_regex_is_empty_match_only() {
        let got = hits("a*", "baa");
        assert!(got.iter().all(|h| h.start != h.end));
        assert_eq!(got, vec![(1, 3)]);
    }
}

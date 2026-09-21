//! 极简 JSON：仅使用标准库，保证对象键顺序（链式摘要与审计导出依赖确定性）。

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Self {
        Value::Str(s.into())
    }

    pub fn obj(pairs: Vec<(&str, Value)>) -> Self {
        Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn from_pairs(pairs: Vec<(String, Value)>) -> Self {
        Value::Obj(pairs)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }

    pub fn into_object(self) -> Option<Vec<(String, Value)>> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
}

pub fn stringify(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

pub fn write_pretty(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Obj(pairs) if pairs.is_empty() => out.push_str("{}"),
        Value::Arr(items) if items.is_empty() => out.push_str("[]"),
        Value::Obj(pairs) => {
            out.push_str("{\n");
            for (i, (k, v)) in pairs.iter().enumerate() {
                push_indent(out, indent + 1);
                out.push('"');
                escape_into(k, out);
                out.push_str("\": ");
                write_pretty(out, v, indent + 1);
                if i + 1 < pairs.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, indent);
            out.push('}');
        }
        Value::Arr(items) => {
            out.push_str("[\n");
            for (i, v) in items.iter().enumerate() {
                push_indent(out, indent + 1);
                write_pretty(out, v, indent + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, indent);
            out.push(']');
        }
        other => write_value(out, other),
    }
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => out.push_str(n),
        Value::Str(s) => {
            out.push('"');
            escape_into(s, out);
            out.push('"');
        }
        Value::Arr(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, v);
            }
            out.push(']');
        }
        Value::Obj(pairs) => {
            out.push('{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_into(k, out);
                out.push_str("\":");
                write_value(out, v);
            }
            out.push('}');
        }
    }
}

fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let bytes = input.as_bytes();
    let mut pos = 0;
    skip_ws(bytes, &mut pos);
    let value = parse_value(bytes, &mut pos)?;
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return Err(format!("unexpected trailing data at {}", pos));
    }
    Ok(value)
}

fn skip_ws(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], b' ' | b'\t' | b'\n' | b'\r') {
        *pos += 1;
    }
}

fn parse_value(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    skip_ws(b, pos);
    if *pos >= b.len() {
        return Err("unexpected end".into());
    }
    match b[*pos] {
        b'{' => parse_object(b, pos),
        b'[' => parse_array(b, pos),
        b'"' => parse_string(b, pos).map(Value::Str),
        b't' | b'f' => parse_bool(b, pos),
        b'n' => parse_null(b, pos),
        c if c == b'-' || c.is_ascii_digit() => parse_number(b, pos),
        other => Err(format!("unexpected byte {} at {}", other as char, pos)),
    }
}

fn parse_object(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1;
    let mut pairs: Vec<(String, Value)> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b'}' {
        *pos += 1;
        return Ok(Value::Obj(pairs));
    }
    loop {
        skip_ws(b, pos);
        let key = parse_string(b, pos)?;
        if seen.contains_key(&key) {
            return Err(format!("duplicate key: {}", key));
        }
        seen.insert(key.clone(), ());
        skip_ws(b, pos);
        expect(b, pos, b':')?;
        let value = parse_value(b, pos)?;
        pairs.push((key, value));
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(b',') => {
                *pos += 1;
            }
            Some(b'}') => {
                *pos += 1;
                break;
            }
            _ => return Err(format!("expected , or }} at {}", pos)),
        }
    }
    Ok(Value::Obj(pairs))
}

fn parse_array(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1;
    let mut items = Vec::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b']' {
        *pos += 1;
        return Ok(Value::Arr(items));
    }
    loop {
        let value = parse_value(b, pos)?;
        items.push(value);
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(b',') => {
                *pos += 1;
            }
            Some(b']') => {
                *pos += 1;
                break;
            }
            _ => return Err(format!("expected , or ] at {}", pos)),
        }
    }
    Ok(Value::Arr(items))
}

fn parse_string(b: &[u8], pos: &mut usize) -> Result<String, String> {
    expect(b, pos, b'"')?;
    let mut s = String::new();
    loop {
        if *pos >= b.len() {
            return Err("unterminated string".into());
        }
        let c = b[*pos];
        *pos += 1;
        match c {
            b'"' => break,
            b'\\' => {
                if *pos >= b.len() {
                    return Err("bad escape".into());
                }
                let e = b[*pos];
                *pos += 1;
                match e {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/' => s.push('/'),
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'b' => s.push('\u{08}'),
                    b'f' => s.push('\u{0c}'),
                    b'u' => {
                        if *pos + 4 > b.len() {
                            return Err("bad unicode escape".into());
                        }
                        let hex = std::str::from_utf8(&b[*pos..*pos + 4]).unwrap();
                        *pos += 4;
                        let code = u32::from_str_radix(hex, 16)
                            .map_err(|_| "bad unicode hex".to_string())?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if *pos + 6 > b.len() || b[*pos] != b'\\' || b[*pos + 1] != b'u' {
                                return Err("expected low surrogate".into());
                            }
                            let lo_hex =
                                std::str::from_utf8(&b[*pos + 2..*pos + 6]).unwrap();
                            let lo = u32::from_str_radix(lo_hex, 16)
                                .map_err(|_| "bad surrogate hex".to_string())?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err("bad low surrogate".into());
                            }
                            *pos += 6;
                            let cval = 0x10000
                                + ((code - 0xD800) << 10)
                                + (lo - 0xDC00);
                            s.push(char::from_u32(cval).ok_or("invalid codepoint")?);
                        } else {
                            s.push(char::from_u32(code).ok_or("invalid codepoint")?);
                        }
                    }
                    _ => return Err("bad escape".into()),
                }
            }
            _ => {
                let start = *pos - 1;
                let end = if c < 0x80 {
                    *pos
                } else {
                    let width = if c >= 0xF0 {
                        4
                    } else if c >= 0xE0 {
                        3
                    } else {
                        2
                    };
                    (*pos - 1 + width).min(b.len())
                };
                let slice = &b[start..end];
                let st = std::str::from_utf8(slice).map_err(|_| "bad utf8".to_string())?;
                s.push_str(st);
                *pos = end;
            }
        }
    }
    Ok(s)
}

fn parse_bool(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    if b.len() >= *pos + 4 && &b[*pos..*pos + 4] == b"true" {
        *pos += 4;
        Ok(Value::Bool(true))
    } else if b.len() >= *pos + 5 && &b[*pos..*pos + 5] == b"false" {
        *pos += 5;
        Ok(Value::Bool(false))
    } else {
        Err("bad literal".into())
    }
}

fn parse_null(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    if b.len() >= *pos + 4 && &b[*pos..*pos + 4] == b"null" {
        *pos += 4;
        Ok(Value::Null)
    } else {
        Err("bad literal".into())
    }
}

fn parse_number(b: &[u8], pos: &mut usize) -> Result<Value, String> {
    let start = *pos;
    if b[*pos] == b'-' {
        *pos += 1;
    }
    while *pos < b.len()
        && (b[*pos].is_ascii_digit() || matches!(b[*pos], b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        *pos += 1;
    }
    let text = std::str::from_utf8(&b[start..*pos]).map_err(|_| "bad number".to_string())?;
    text.parse::<f64>().map_err(|_| format!("bad number: {}", text))?;
    Ok(Value::Num(text.to_string()))
}

fn expect(b: &[u8], pos: &mut usize, c: u8) -> Result<(), String> {
    if *pos >= b.len() || b[*pos] != c {
        return Err(format!("expected {} at {}", c as char, pos));
    }
    *pos += 1;
    Ok(())
}

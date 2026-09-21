//! 极简本地 HTTP/1.1 服务（仅标准库 + 线程，每连接独立线程）。

use gsb_maskroom::engine::{Engine, RuleInput};
use gsb_maskroom::model::EngineError;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = idx + 4;
            let head = String::from_utf8_lossy(&buf[..idx]).to_string();
            let mut lines = head.split("\r\n");
            let request_line = lines.next()?;
            let mut parts = request_line.split(' ');
            let method = parts.next()?.to_string();
            let target = parts.next()?.to_string();
            let mut content_length = 0usize;
            for line in lines {
                if let Some(rest) = line
                    .split_once(':')
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim()))
                {
                    if rest.0 == "content-length" {
                        content_length = rest.1.parse().ok()?;
                    }
                }
            }
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut tmp).ok()?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(content_length);
            return Some(Request { method, path: target, body });
        }
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 16 * 1024 * 1024 {
            return None;
        }
    }
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn json_response(stream: &mut TcpStream, status: u16, value: &Value) {
    write_response(stream, status, "application/json; charset=utf-8", serde_json::to_vec(value).unwrap().as_slice());
}

fn err_response(stream: &mut TcpStream, e: &EngineError) {
    let status = e.http_status();
    let body = json!({"error": {"code": e.code(), "message": e.message()}});
    json_response(stream, status, &body);
}

fn parse_body(body: &[u8]) -> Result<Value, EngineError> {
    serde_json::from_slice(body).map_err(|_| EngineError::BadInput("请求体必须是 JSON".into()))
}

fn field_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, EngineError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| EngineError::BadInput(format!("缺少字符串字段 {key}")))
}

pub fn serve(addr: String, engine: Arc<Engine>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr)?;
    println!("浏览器访问：http://{addr}");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
            if let Some(req) = read_request(&mut stream) {
                handle(&mut stream, &engine, req);
            }
        });
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, engine: &Arc<Engine>, req: Request) {
    let result = route(stream, engine, req);
    if let Err(e) = result {
        err_response(stream, &e);
    }
}

fn route(stream: &mut TcpStream, engine: &Arc<Engine>, req: Request) -> Result<(), EngineError> {
    let path = req.path.as_str();
    let route = path.split('?').next().unwrap_or(path);
    if req.method == "GET" && (route == "/" || route == "/index.html") {
        write_response(stream, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes());
        return Ok(());
    }
    if req.method == "GET" && route == "/app.js" {
        write_response(stream, 200, "application/javascript; charset=utf-8", APP_JS.as_bytes());
        return Ok(());
    }

    // ---- 健康检查 ----
    if req.method == "GET" && route == "/api/health" {
        json_response(stream, 200, &json!({"ok": true, "service": "maskroom"}));
        return Ok(());
    }

    // ---- 租户 ----
    if req.method == "GET" && route == "/api/tenants" {
        json_response(stream, 200, &json!({"tenants": engine.list_tenants()}));
        return Ok(());
    }
    if req.method == "POST" && route == "/api/tenants" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        engine.create_tenant(tenant)?;
        json_response(stream, 200, &json!({"ok": true, "tenant": tenant}));
        return Ok(());
    }

    // ---- 规则 ----
    if req.method == "GET" && path.starts_with("/api/rules?") {
        let tenant = query_param(&req.path, "tenant")
            .ok_or_else(|| EngineError::BadInput("缺少 tenant 查询参数".into()))?;
        let meta = engine.list_rules(&tenant)?;
        json_response(stream, 200, &serde_json::to_value(meta).unwrap());
        return Ok(());
    }
    if req.method == "POST" && route == "/api/rules" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let input: RuleInput =
            serde_json::from_value(body.clone()).map_err(|e| EngineError::BadInput(e.to_string()))?;
        let view = engine.upsert_rule(tenant, input)?;
        json_response(stream, 200, &serde_json::to_value(view).unwrap());
        return Ok(());
    }
    if req.method == "POST" && route == "/api/rules/delete" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let rule_id = field_str(&body, "rule_id")?;
        let version = engine.delete_rule(tenant, rule_id)?;
        json_response(stream, 200, &json!({"ok": true, "rule_version": version}));
        return Ok(());
    }
    if req.method == "POST" && route == "/api/rules/toggle" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let rule_id = field_str(&body, "rule_id")?;
        let enabled = body
            .get("enabled")
            .and_then(|x| x.as_bool())
            .ok_or_else(|| EngineError::BadInput("缺少布尔字段 enabled".into()))?;
        let version = engine.set_rule_enabled(tenant, rule_id, enabled)?;
        json_response(stream, 200, &json!({"ok": true, "rule_version": version}));
        return Ok(());
    }

    // ---- 脱敏 / 预览 ----
    if req.method == "POST" && route == "/api/redact" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let text = field_str(&body, "text")?;
        let out = engine.redact(tenant, text)?;
        json_response(stream, 200, &serde_json::to_value(out).unwrap());
        return Ok(());
    }
    if req.method == "POST" && route == "/api/preview" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let text = field_str(&body, "text")?;
        let out = engine.preview(tenant, text)?;
        json_response(stream, 200, &serde_json::to_value(out).unwrap());
        return Ok(());
    }

    // ---- 还原 ----
    if req.method == "POST" && route == "/api/restore" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let token = field_str(&body, "token")?;
        let purpose = field_str(&body, "purpose")?;
        let original = engine.restore(tenant, token, purpose)?;
        json_response(stream, 200, &json!({"ok": true, "original": original}));
        return Ok(());
    }
    if req.method == "POST" && route == "/api/restore-batch" {
        let body = parse_body(&req.body)?;
        let tenant = field_str(&body, "tenant")?;
        let items_val = body
            .get("items")
            .and_then(|x| x.as_array())
            .ok_or_else(|| EngineError::BadInput("缺少 items 数组".into()))?;
        let mut items = Vec::new();
        for it in items_val {
            let token = field_str(it, "token")?;
            let purpose = field_str(it, "purpose")?;
            items.push((token.to_string(), purpose.to_string()));
        }
        let out = engine.restore_batch(tenant, items)?;
        json_response(stream, 200, &json!({"results": out}));
        return Ok(());
    }

    // ---- 轮换 / 审计 / 导出 ----
    if req.method == "POST" && route == "/api/keys/rotate" {
        let info = engine.rotate_key()?;
        json_response(stream, 200, &info);
        return Ok(());
    }
    if req.method == "GET" && route == "/api/keys" {
        json_response(stream, 200, &engine.key_info());
        return Ok(());
    }
    if req.method == "GET" && path.starts_with("/api/audit?") {
        let tenant = query_param(&req.path, "tenant");
        let limit = query_param(&req.path, "limit").and_then(|x| x.parse::<usize>().ok());
        let entries = engine.read_audit(tenant.as_deref(), limit)?;
        json_response(stream, 200, &json!({"entries": entries}));
        return Ok(());
    }
    if req.method == "GET" && route == "/api/audit/verify" {
        let summary = engine.verify_audit()?;
        json_response(stream, 200, &serde_json::to_value(summary).unwrap());
        return Ok(());
    }
    if req.method == "GET" && route == "/api/export" {
        let bundle = engine.export()?;
        json_response(stream, 200, &serde_json::to_value(bundle).unwrap());
        return Ok(());
    }

    json_response(
        stream,
        404,
        &json!({"error": {"code": "not_found", "message": "接口不存在"}}),
    );
    Ok(())
}

fn query_param(target: &str, key: &str) -> Option<String> {
    let q = target.split_once('?')?.1;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

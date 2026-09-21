//! 端到端：启动真实二进制，走通页面与全部 HTTP 接口。
mod common;
use common::TempDir;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct Server {
    child: Child,
    addr: String,
    _dir: TempDir,
}

impl Server {
    fn start(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let port = free_port();
        let bin = env!("CARGO_BIN_EXE_gsb-maskroom");
        let child = Command::new(bin)
            .arg("--addr")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--data-dir")
            .arg(dir.path())
            .spawn()
            .expect("启动服务器");
        let addr = format!("127.0.0.1:{port}");
        let srv = Server { child, addr, _dir: dir };
        // 等待端口就绪。
        for _ in 0..50 {
            if TcpStream::connect(&srv.addr).is_ok() {
                return srv;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("服务器未在预期时间内启动");
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        let mut stream = TcpStream::connect(&self.addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        match (method, body) {
            ("GET", _) => {
                let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                stream.write_all(req.as_bytes()).unwrap();
            }
            (_, Some(b)) => {
                let req = format!(
                    "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    b.len(),
                    b
                );
                stream.write_all(req.as_bytes()).unwrap();
            }
            _ => panic!("unsupported"),
        }
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&raw).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn full_workflow_over_http() {
    let srv = Server::start("http");

    // 首页必须出现“脱敏映射室”。
    let (status, html) = srv.request("GET", "/", None);
    assert_eq!(status, 200);
    assert!(html.contains("脱敏映射室"), "首页标题缺失");
    assert!(html.contains("/app.js"));
    let (s2, appjs) = srv.request("GET", "/app.js", None);
    assert_eq!(s2, 200);
    assert!(appjs.contains("restore-batch") || appjs.contains("/api/"));

    // 建租户 + 规则。
    let (s, _) = srv.request("POST", "/api/tenants", Some(r#"{"tenant":"acme"}"#));
    assert_eq!(s, 200);
    let rule = r#"{"tenant":"acme","name":"邮箱","type":"email","priority":10,"stable":true}"#;
    let (s, b) = srv.request("POST", "/api/rules", Some(rule));
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("\"rule_version\":1"));

    // 脱敏。
    let (s, b) = srv.request(
        "POST",
        "/api/redact",
        Some(r#"{"tenant":"acme","text":"联系 alice@example.com 谢谢"}"#),
    );
    assert_eq!(s, 200);
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    let token = v["accepted"][0]["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("MTKN-G1-"));
    assert!(v["text"].as_str().unwrap().contains(&token));

    // 还原成功。
    let body = format!(r#"{{"tenant":"acme","token":"{token}","purpose":"客服核对"}}"#);
    let (s, b) = srv.request("POST", "/api/restore", Some(&body));
    assert_eq!(s, 200);
    assert!(b.contains("alice@example.com"));

    // 还原失败：统一错误。
    let (s, b) = srv.request(
        "POST",
        "/api/restore",
        Some(r#"{"tenant":"acme","token":"MTKN-G1-aaaaaaaaaaaaaaaaaaaa-aaaaaaaaaaa","purpose":"x"}"#),
    );
    assert_eq!(s, 422);
    assert!(b.contains("invalid_token"));
    assert!(!b.contains("acme"));

    // 轮换。
    let (s, b) = srv.request("POST", "/api/keys/rotate", Some("{}"));
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("\"current_generation\":2"));

    // 审计校验。
    let (s, b) = srv.request("GET", "/api/audit/verify", None);
    assert_eq!(s, 200);
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["entries"].as_u64().unwrap() >= 5);

    // 审计列表包含成功与失败。
    let (s, b) = srv.request("GET", "/api/audit?limit=50", None);
    assert_eq!(s, 200);
    assert!(b.contains("restore-ok") && b.contains("restore-denied") && b.contains("key-rotation"));

    // 导出不含原文。
    let (s, b) = srv.request("GET", "/api/export", None);
    assert_eq!(s, 200);
    assert!(b.contains("MTKN-G1-"));
    assert!(!b.contains("alice@example.com"));
    assert!(!b.contains("original_cipher_hex"));

    // 404。
    let (s, _) = srv.request("GET", "/nope", None);
    assert_eq!(s, 404);
}

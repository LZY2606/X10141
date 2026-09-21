use masking_room::crypto::{b64e, GenKey, KeyFile};
use masking_room::service::{Vault, RESTORE_ERROR};
use masking_room::state::{MatchKind, Rule};
use std::fs;

const MASTER: [u8; 32] = [7u8; 32];
const GEN1: [u8; 32] = [9u8; 32];

fn rule(id: &str, version: u32, kind: MatchKind, pattern: &str, priority: i32) -> Rule {
    Rule {
        id: id.to_string(),
        version,
        kind,
        pattern: pattern.to_string(),
        priority,
        description: String::new(),
        stable: true,
    }
}

fn email_rule() -> Rule {
    rule("email", 1, MatchKind::Regex, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 10)
}

fn fresh_vault(dir: &tempfile::TempDir) -> Vault {
    Vault::init_with_keys(dir.path(), MASTER, GEN1).unwrap()
}

fn token_of(outcome: &masking_room::service::RedactOutcome, idx: usize) -> String {
    outcome.tokens[idx].token.clone()
}

#[test]
fn stable_token_same_tenant_and_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    let a = v.redact("tenant-a", "mail alice@example.com now").unwrap();
    let b = v.redact("tenant-a", "again alice@example.com here").unwrap();
    assert_eq!(a.tokens[0].token_id, b.tokens[0].token_id, "同租户+规则版本+原文 => 稳定 token");
    assert_eq!(v.store.state.mappings.len(), 1, "稳定 token 复用同一映射");
}

#[test]
fn cross_tenant_tokens_unlinkable() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    let a = v.redact("tenant-a", "alice@example.com").unwrap();
    let b = v.redact("tenant-b", "alice@example.com").unwrap();
    assert_ne!(a.tokens[0].token_id, b.tokens[0].token_id, "不同租户绝不能产生可关联 token");
    assert_ne!(a.redacted, b.redacted);
    assert_eq!(v.store.state.mappings.len(), 2);
}

#[test]
fn overlap_resolved_by_priority_then_longest() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    v.register_rule(rule("custom-name", 1, MatchKind::Literal, "alice@example", 5)).unwrap();
    v.register_rule(rule("ticket", 1, MatchKind::Regex, r"ID-[0-9]+", 1)).unwrap();
    // 同优先级时最长匹配胜出
    v.register_rule(rule("short", 1, MatchKind::Literal, "ID-123", 3)).unwrap();
    v.register_rule(rule("long", 1, MatchKind::Literal, "ID-12345", 3)).unwrap();

    let text = "联系 alice@example.com 或编号 ID-12345";
    let preview = v.preview(text);
    let accepted_ids: Vec<&str> = preview.accepted.iter().map(|s| s.rule_id.as_str()).collect();
    assert!(accepted_ids.contains(&"email"));
    assert!(accepted_ids.contains(&"long"), "同优先级取最长匹配");
    assert!(!accepted_ids.contains(&"custom-name"));
    assert!(!accepted_ids.contains(&"short"));

    let suppressed: Vec<(&str, &str)> = preview
        .suppressed
        .iter()
        .map(|s| (s.rule_id.as_str(), s.suppressed_by.rule_id.as_str()))
        .collect();
    assert!(suppressed.contains(&("custom-name", "email")), "解释被压下的命中");
    assert!(suppressed.contains(&("short", "long")));
    assert!(suppressed.contains(&("ticket", "long")));

    let out = v.redact("t", text).unwrap();
    assert!(!out.redacted.contains("alice@example.com"));
    assert!(!out.redacted.contains("ID-12345"));
    assert_eq!(out.tokens.len(), 2);
}

#[test]
fn redaction_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    v.register_rule(rule("anyword", 1, MatchKind::Regex, r"[A-Za-z0-9]+", 0)).unwrap();
    let once = v.redact("t", "mail alice@example.com end").unwrap();
    let mappings_before = v.store.state.mappings.len();
    let twice = v.redact("t", &once.redacted).unwrap();
    assert_eq!(once.redacted, twice.redacted, "重复处理必须保持不变");
    assert!(twice.tokens.is_empty(), "token 自身不得再被识别");
    assert_eq!(v.store.state.mappings.len(), mappings_before, "不得产生新映射");
}

#[test]
fn batch_restore_partial_failure_and_uniform_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    let a = v.redact("tenant-a", "alice@example.com").unwrap();
    let b = v.redact("tenant-b", "bob@example.com").unwrap();
    let unknown_wellformed = format!("⟦TKN-{}⟧", "A".repeat(22));
    let garbage = "not-a-token".to_string();

    let results = v.restore(
        "客服回访",
        &[token_of(&a, 0), unknown_wellformed.clone(), token_of(&b, 0), garbage.clone()],
    );
    assert_eq!(results.len(), 4);
    assert!(results[0].ok && results[0].text.as_deref() == Some("alice@example.com"));
    assert!(!results[1].ok, "未知 token 失败");
    assert!(results[2].ok && results[2].text.as_deref() == Some("bob@example.com"), "无效项不影响其他项");
    assert!(!results[3].ok);
    assert_eq!(results[1].error.as_deref(), Some(RESTORE_ERROR));
    assert_eq!(results[3].error.as_deref(), Some(RESTORE_ERROR), "统一错误，不泄露归属");
    assert_eq!(results[1].error, results[3].error);

    // 每次成功与失败都写入审计
    let kinds: Vec<&str> = v.store.state.audit.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds.iter().filter(|k| **k == "restore_ok").count(), 2);
    assert_eq!(kinds.iter().filter(|k| **k == "restore_fail").count(), 2);
}

#[test]
fn rotation_keeps_old_mappings_and_writes_new_gen() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    let before = v.redact("t", "alice@example.com").unwrap();
    let old_token = token_of(&before, 0);

    let new_gen = v.rotate().unwrap();
    assert_eq!(new_gen, 2);
    assert_eq!(v.store.state.current_gen, 2);

    // 旧数据仍可解开
    let res = v.restore("轮换后还原旧 token", &[old_token]);
    assert!(res[0].ok);
    assert_eq!(res[0].text.as_deref(), Some("alice@example.com"));

    // 新写入只用新代次
    let after = v.redact("t", "carol@example.com").unwrap();
    let rec = &v.store.state.mappings[&after.tokens[0].token_id];
    assert_eq!(rec.gen, 2, "新映射必须使用新代次密钥");
    assert_eq!(v.store.state.mappings[&before.tokens[0].token_id].gen, 1);

    // 轮换写入审计
    assert!(v.store.state.audit.iter().any(|a| a.kind == "rotate"));
    assert!(v.verify_audit());
}

#[test]
fn rotation_crash_recovery_is_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    let out = v.redact("t", "alice@example.com").unwrap();
    let token = token_of(&out, 0);
    v.rotate().unwrap(); // 当前代次 = 2
    let audit_len = v.store.state.audit.len();
    drop(v);

    // 模拟轮换到第 3 代时崩溃：keys.json 已含新代次，state.json 未更新，且残留 tmp
    let keys_path = dir.path().join("keys.json");
    let mut keys: KeyFile = serde_json::from_str(&fs::read_to_string(&keys_path).unwrap()).unwrap();
    keys.generations.push(GenKey { id: 3, key_b64: b64e(&[3u8; 32]) });
    fs::write(&keys_path, serde_json::to_vec_pretty(&keys).unwrap()).unwrap();
    fs::write(dir.path().join("state.json.tmp"), b"half-written-state").unwrap();

    // 重启恢复：状态与审计一致地指向旧代次，不存在一半新一半旧
    let mut v2 = Vault::load(dir.path()).unwrap();
    assert_eq!(v2.store.state.current_gen, 2);
    assert!(v2.verify_audit(), "审计链在崩溃恢复后必须完整");
    assert_eq!(v2.store.state.audit.len(), audit_len);
    assert!(!dir.path().join("state.json.tmp").exists(), "残留临时文件被清理");
    assert!(v2.store.state.mappings.values().all(|m| m.gen <= 2), "不得出现指向未启用代次的映射");

    // 旧数据仍可解开，新写入仍用当前（旧）代次
    let res = v2.restore("崩溃恢复后", &[token]);
    assert!(res[0].ok);
    let out2 = v2.redact("t", "dave@example.com").unwrap();
    assert_eq!(v2.store.state.mappings[&out2.tokens[0].token_id].gen, 2);

    // 之后可以正常继续轮换
    let gen = v2.rotate().unwrap();
    assert_eq!(gen, 4, "新代次跳过已写入但未启用的第 3 代");
    assert!(v2.verify_audit());
}

#[test]
fn audit_tampering_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    v.redact("t", "alice@example.com").unwrap();
    assert!(v.verify_audit());

    // 内存中篡改
    let mut tampered = v.store.state.clone();
    tampered.audit[1].detail = serde_json::json!({"tenant": "attacker"});
    let mut v2 = Vault::load(dir.path()).unwrap();
    v2.store.state = tampered;
    assert!(!v2.verify_audit(), "篡改审计内容必须被检测");

    // 磁盘上篡改后重新加载
    let state_path = dir.path().join("state.json");
    let mut disk: serde_json::Value = serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    disk["audit"][0]["kind"] = serde_json::json!("redact");
    fs::write(&state_path, serde_json::to_vec_pretty(&disk).unwrap()).unwrap();
    let v3 = Vault::load(dir.path()).unwrap();
    assert!(!v3.verify_audit(), "无痕改写必须被链式摘要发现");
}

#[test]
fn export_contains_no_plaintext_mappings() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    v.register_rule(email_rule()).unwrap();
    v.redact("tenant-a", "secret alice@example.com").unwrap();
    v.restore("导出前还原", &["⟦TKN-AAAAAAAAAAAAAAAAAAAAAA⟧".to_string()]);

    let export = v.export();
    let json = serde_json::to_string(&export).unwrap();
    assert!(!json.contains("alice@example.com"), "导出不得包含原文");
    assert!(!json.contains("ciphertext_b64"), "导出不得包含映射密文");
    assert!(json.contains("email"), "导出包含规则元数据");
    assert!(json.contains("hashes"), "导出包含审计摘要");
    assert_eq!(export.redacted_texts.len(), 1);
    assert!(export.redacted_texts[0].redacted_text.contains("⟦TKN-"));
}

#[test]
fn state_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let token;
    {
        let mut v = fresh_vault(&dir);
        v.register_rule(email_rule()).unwrap();
        token = token_of(&v.redact("t", "alice@example.com").unwrap(), 0);
    }
    let mut v2 = Vault::load(dir.path()).unwrap();
    assert_eq!(v2.store.state.rules.len(), 1);
    let res = v2.restore("重启后还原", &[token]);
    assert!(res[0].ok);
    assert_eq!(res[0].text.as_deref(), Some("alice@example.com"));
    assert!(v2.verify_audit());
}

#[test]
fn unstable_rule_produces_fresh_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fresh_vault(&dir);
    let mut r = email_rule();
    r.stable = false;
    v.register_rule(r).unwrap();
    let a = v.redact("t", "alice@example.com").unwrap();
    let b = v.redact("t", "alice@example.com").unwrap();
    assert_ne!(a.tokens[0].token_id, b.tokens[0].token_id, "非稳定规则每次生成新 token");
    assert_eq!(v.store.state.mappings.len(), 2);
}

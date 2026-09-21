mod common;

use common::*;
use gsb_maskroom::engine::{CrashPoint, RuleInput};
use serde_json::json;

fn email_rule(prio: i32, stable: bool) -> RuleInput {
    RuleInput {
        id: None,
        name: "邮箱".into(),
        kind: Some("email".into()),
        pattern: None,
        min: None,
        max: None,
        priority: Some(prio),
        stable: Some(stable),
        enabled: Some(true),
    }
}

fn regex_rule(name: &str, pattern: &str, prio: i32, stable: bool) -> RuleInput {
    RuleInput {
        id: None,
        name: name.into(),
        kind: Some("regex".into()),
        pattern: Some(pattern.into()),
        min: None,
        max: None,
        priority: Some(prio),
        stable: Some(stable),
        enabled: Some(true),
    }
}

fn range_rule(name: &str, min: i64, max: i64, prio: i32, stable: bool) -> RuleInput {
    RuleInput {
        id: None,
        name: name.into(),
        kind: Some("range".into()),
        pattern: None,
        min: Some(json!(min)),
        max: Some(json!(max)),
        priority: Some(prio),
        stable: Some(stable),
        enabled: Some(true),
    }
}

// ---- 跨租户不可关联 ----

#[test]
fn cross_tenant_tokens_are_unlinkable() {
    let (_d, e) = test_engine("cross", b"seed-cross");
    e.create_tenant("alpha").unwrap();
    e.create_tenant("beta").unwrap();
    e.upsert_rule("alpha", email_rule(10, true)).unwrap();
    e.upsert_rule("beta", email_rule(10, true)).unwrap();

    let text = "联系 alice@example.com 谢谢";
    let a = e.redact("alpha", text).unwrap();
    let b = e.redact("beta", text).unwrap();
    let ta = a.accepted[0].token.clone().unwrap();
    let tb = b.accepted[0].token.clone().unwrap();

    // 同原文、同规则版本，但 token 完全不同，且彼此都验不过对方标签。
    assert_ne!(ta, tb, "不同租户不得产生相同 token");

    // alpha 无法把 beta 的 token 还原（即使原文相同）。
    let err = e.restore("alpha", &tb, "尝试越权").unwrap_err();
    assert_eq!(err.code(), "invalid_token");
    let err2 = e.restore("beta", &ta, "尝试越权").unwrap_err();
    assert_eq!(err2.code(), "invalid_token");

    // 错误信息统一，不泄露归属。
    assert_eq!(
        err.message(),
        "token 无效、已失效或不属于当前租户"
    );
    // 随机稳定方式下，不同租户稳定 ID 也不同：从导出看不到原文。
}

#[test]
fn unknown_tenant_token_gives_same_unified_error() {
    let (_d, e) = test_engine("unknown", b"seed-unknown");
    e.create_tenant("alpha").unwrap();
    e.upsert_rule("alpha", email_rule(10, false)).unwrap();
    let out = e.redact("alpha", "x@y.com 来件").unwrap();
    let tok = out.accepted[0].token.clone().unwrap();

    // 另一租户：完全相同的错误码与文案。
    e.create_tenant("gamma").unwrap();
    let cross = e.restore("gamma", &tok, "越权").unwrap_err();
    // 格式错误：同样的统一错误。
    let malformed = e.restore("gamma", "MTKN-G1-aaaaaaaaaaaaaaaaaaaa-zzzzzzzzzzz", "x").unwrap_err();
    assert_eq!(cross.code(), malformed.code());
    assert_eq!(cross.message(), malformed.message());
    // 直接瞎写的字符串也是同一错误。
    let bogus = e.restore("gamma", "not-a-token", "x").unwrap_err();
    assert_eq!(bogus.code(), "invalid_token");
}

// ---- 稳定 token ----

#[test]
fn stable_tokens_reuse_within_version_and_change_after_rule_change() {
    let (_d, e) = test_engine("stable", b"seed-stable");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();

    let first = e.redact("t", "a a@b.com").unwrap();
    let tok1 = first.accepted[0].token.clone().unwrap();
    let again = e.redact("t", "b a@b.com").unwrap();
    let tok2 = again.accepted[0].token.clone().unwrap();
    assert_eq!(tok1, tok2, "同版本同原文必须稳定");
    assert_eq!(e.mapping_count_for_test("t").unwrap(), 1, "稳定映射只写一次");

    // 规则集产生新版本后，稳定标识随之变化，旧 token 仍可还原。
    e.upsert_rule("t", regex_rule("补充", r"\d+", 1, false)).unwrap();
    let after = e.redact("t", "c a@b.com").unwrap();
    let tok3 = after
        .accepted
        .iter()
        .find(|h| h.rule_name == "邮箱")
        .unwrap()
        .token
        .clone()
        .unwrap();
    assert_ne!(tok1, tok3, "规则版本变化后稳定 token 必须不同");
    // 旧 token 仍能解开（旧代次+旧映射保留）。
    assert_eq!(e.restore("t", &tok1, "旧版本核对").unwrap(), "a@b.com");
    assert_eq!(e.restore("t", &tok3, "新版本核对").unwrap(), "a@b.com");
}

#[test]
fn random_tokens_differ_each_time() {
    let (_d, e) = test_engine("random", b"seed-random");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, false)).unwrap();
    let t1 = e.redact("t", "a@b.com x").unwrap().accepted[0].token.clone().unwrap();
    let t2 = e.redact("t", "a@b.com y").unwrap().accepted[0].token.clone().unwrap();
    assert_ne!(t1, t2, "随机 token 每次不同");
    assert_ne!(t1, t2);
    assert_eq!(e.mapping_count_for_test("t").unwrap(), 2);
}

// ---- 重叠裁决 ----

#[test]
fn overlap_adjudication_priority_then_longest() {
    let (_d, e) = test_engine("overlap", b"seed-overlap");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    // 低优先级但覆盖更长的整段（含中文+空格+邮箱）。
    e.upsert_rule("t", regex_rule("宽匹配", r"\S+\s\S+", 1, false)).unwrap();
    // 与邮箱同优先级但更短的局部匹配，验证“最长匹配”。
    e.upsert_rule("t", regex_rule("域名", r"@\S+", 10, false)).unwrap();
    // 编号范围与邮箱不重叠，但与宽匹配重叠：邮箱压下宽匹配后，编号仍应存活。
    e.upsert_rule("t", range_rule("编号", 2000, 2100, 5, true)).unwrap();

    let preview = e.preview("t", "邮箱 a@b.com 编号2048").unwrap();
    let names: Vec<&str> = preview.accepted.iter().map(|h| h.rule_name.as_str()).collect();
    assert!(names.contains(&"邮箱"), "邮箱应胜出：更高优先级");
    assert!(names.contains(&"编号"), "不与邮箱重叠的编号必须存活");
    assert!(!names.contains(&"宽匹配"), "低优先级宽匹配应被压下");
    assert!(!names.contains(&"域名"), "同优先级较短匹配应被压下");

    let reasons: Vec<&str> = preview.suppressed.iter().map(|s| s.reason.as_str()).collect();
    assert!(reasons.contains(&"overlap-higher-priority"));
    assert!(reasons.contains(&"overlap-longer-match") || reasons.contains(&"overlap-stable-tiebreak"));

    // 真正执行脱敏也保持同样裁决。
    let out = e.redact("t", "邮箱 a@b.com 编号2048").unwrap();
    assert_eq!(out.accepted.len(), 2);
    assert_eq!(out.suppressed.len(), preview.suppressed.len());
}

// ---- 重复处理幂等：token 不被再识别 ----

#[test]
fn reprocessing_is_idempotent() {
    let (_d, e) = test_engine("idempotent", b"seed-idem");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    e.upsert_rule("t", range_rule("编号", 2000, 2100, 10, true)).unwrap();

    let original = "邮件 a@b.com 与编号 2048 完成";
    let first = e.redact("t", original).unwrap();
    assert!(first.text.starts_with("邮件 MTKN-G1-"));
    let second = e.redact("t", &first.text).unwrap();
    let third = e.redact("t", &second.text).unwrap();
    assert_eq!(first.text, second.text, "第二次处理必须保持不变");
    assert_eq!(second.text, third.text);
    assert_eq!(second.accepted.len(), 0, "已脱敏文本不应产生新的敏感命中");
    assert_eq!(second.token_protected, 2, "应识别出 2 个既有 token 并保护");
    assert!(second.suppressed.iter().all(|s| s.reason == "inside-existing-token"));

    // 原始内容仍能完整还原。
    for h in first.accepted.iter() {
        let tok = h.token.as_ref().unwrap();
        let back = e.restore("t", tok, "核对").unwrap();
        assert!(original.contains(&back));
    }
}

#[test]
fn foreign_token_is_not_protected_and_email_inside_text_still_detected() {
    // 别的租户的 token 对当前租户而言只是普通文本；它不含敏感模式，故不会被处理。
    let (_d, e) = test_engine("foreign", b"seed-foreign");
    e.create_tenant("a").unwrap();
    e.create_tenant("b").unwrap();
    e.upsert_rule("a", email_rule(10, true)).unwrap();
    e.upsert_rule("b", email_rule(10, true)).unwrap();
    let out_a = e.redact("a", "secret a@b.com").unwrap();
    let tok_a = out_a.accepted[0].token.clone().unwrap();

    let out_b = e.redact("b", &format!("引用 {tok_a} 无敏感")).unwrap();
    assert_eq!(out_b.accepted.len(), 0);
    assert_eq!(out_b.text, format!("引用 {tok_a} 无敏感"));
    assert_eq!(out_b.token_protected, 0, "他租户 token 不受本租户保护，也不被识别");
}

// ---- 批量部分失败 + 统一错误 ----

#[test]
fn batch_restore_partial_failure_is_isolated_and_uniform() {
    let (_d, e) = test_engine("batch", b"seed-batch");
    e.create_tenant("t").unwrap();
    e.create_tenant("u").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    e.upsert_rule("u", email_rule(10, true)).unwrap();
    let r1 = e.redact("t", "one@a.com").unwrap().accepted[0].token.clone().unwrap();
    let r2 = e.redact("t", "two@a.com").unwrap().accepted[0].token.clone().unwrap();
    let foreign = e.redact("u", "one@a.com").unwrap().accepted[0].token.clone().unwrap();

    let items = vec![
        (r1.clone(), "用途一".to_string()),
        ("MTKN-G1-deadbeefdeadbeefdead-deadbeefdead".to_string(), "用途二".to_string()),
        (foreign.clone(), "用途三".to_string()),
        ("随便写的".to_string(), "用途四".to_string()),
        (r2.clone(), "用途五".to_string()),
    ];
    let results = e.restore_batch("t", items).unwrap();
    assert_eq!(results.len(), 5);
    assert!(results[0].ok && results[0].original.as_deref() == Some("one@a.com"));
    assert!(!results[1].ok && results[1].original.is_none());
    assert!(!results[2].ok && results[2].original.is_none(), "他租户 token 必须失败");
    assert!(!results[3].ok && results[3].original.is_none());
    assert!(results[4].ok && results[4].original.as_deref() == Some("two@a.com"));
    // 三个失败的提示完全一致，无法据此判断“格式错”还是“属于别的租户”。
    let msg = &results[1].error;
    for i in [1, 2, 3] {
        assert_eq!(results[i].error.as_ref(), msg.as_ref());
    }
}

// ---- 密钥轮换与崩溃恢复 ----

#[test]
fn rotation_retains_old_data_and_uses_new_generation_for_writes() {
    let (dir, e) = test_engine("rotate", b"seed-rotate");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();

    let old = e.redact("t", "旧 old@a.com").unwrap();
    let old_tok = old.accepted[0].token.clone().unwrap();
    assert_eq!(old.key_generation, 1);
    assert!(old_tok.starts_with("MTKN-G1-"));

    e.rotate_key().unwrap();
    assert_eq!(e.current_write_generation(), 2);

    // 新写入使用 G2。
    let new = e.redact("t", "新 new@b.com").unwrap();
    assert_eq!(new.key_generation, 2);
    let new_tok = new.accepted[0].token.clone().unwrap();
    assert!(new_tok.starts_with("MTKN-G2-"));

    // 旧数据仍可解开；新数据也能解开。
    assert_eq!(e.restore("t", &old_tok, "旧数据核对").unwrap(), "old@a.com");
    assert_eq!(e.restore("t", &new_tok, "新数据核对").unwrap(), "new@b.com");

    let gens = e.mapping_generations_for_test("t").unwrap();
    assert!(gens.contains(&1) && gens.contains(&2));

    // 重开进程后仍一致。
    let e2 = reopen(dir.path(), b"seed-rotate", fixed_clock(1_700_000_100));
    assert_eq!(e2.current_write_generation(), 2);
    assert_eq!(e2.restore("t", &old_tok, "重开后旧数据").unwrap(), "old@a.com");
    assert_eq!(e2.restore("t", &new_tok, "重开后新数据").unwrap(), "new@b.com");
    assert!(e2.verify_audit().unwrap().ok);
}

#[test]
fn rotation_crash_after_key_written_rolls_back() {
    let (dir, e) = test_engine("crash1", b"seed-crash1");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    let before = e.redact("t", "a@a.com").unwrap();
    assert!(before.text.contains("MTKN-G1-"));

    // 在“新密钥已写盘、尚未提升”处崩溃。
    e.set_crash_point(Some(CrashPoint::AfterKeyWritten));
    let err = e.rotate_key().unwrap_err();
    assert_eq!(err.code(), "conflict");

    // 重启：检测到未提升的新代次且无数据引用 -> 回滚，仍停留在 G1。
    let e2 = reopen(dir.path(), b"seed-crash1", fixed_clock(1_700_000_100));
    assert_eq!(e2.current_write_generation(), 1);
    let after = e2.redact("t", "b@b.com").unwrap();
    assert!(after.accepted[0].token.clone().unwrap().starts_with("MTKN-G1-"));
    let info = e2.key_info();
    assert_eq!(info["retained_generations"].as_array().unwrap().len(), 1);
    assert!(e2.verify_audit().unwrap().ok);
}

#[test]
fn rotation_crash_after_promoted_commits_forward() {
    let (dir, e) = test_engine("crash2", b"seed-crash2");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    let old = e.redact("t", "old@a.com").unwrap();
    let old_tok = old.accepted[0].token.clone().unwrap();

    e.set_crash_point(Some(CrashPoint::AfterPromoted));
    let _ = e.rotate_key().unwrap_err();

    // 重启：密钥已提升为 G2，但状态/审计还指向旧 -> 必须前向完成，二者一致。
    let e2 = reopen(dir.path(), b"seed-crash2", fixed_clock(1_700_000_100));
    assert_eq!(e2.current_write_generation(), 2);
    assert_eq!(e2.key_info()["current_generation"], 2);
    assert_eq!(e2.key_info()["pending"], serde_json::Value::Null);

    // 不会出现“映射写新代次、审计指旧代次”：后续写入、还原、审计均一致。
    let new = e2.redact("t", "new@b.com").unwrap();
    assert!(new.accepted[0].token.clone().unwrap().starts_with("MTKN-G2-"));
    assert_eq!(new.key_generation, 2);
    assert_eq!(e2.restore("t", &old_tok, "旧数据").unwrap(), "old@a.com");
    assert!(e2.verify_audit().unwrap().ok);

    // 再重开一次依然稳定。
    let e3 = reopen(dir.path(), b"seed-crash2", fixed_clock(1_700_000_200));
    assert_eq!(e3.current_write_generation(), 2);
    assert!(e3.verify_audit().unwrap().ok);
}

#[test]
fn rotation_crash_after_state_also_commits_forward() {
    let (dir, e) = test_engine("crash3", b"seed-crash3");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    e.redact("t", "old@a.com").unwrap();

    e.set_crash_point(Some(CrashPoint::AfterState));
    let _ = e.rotate_key().unwrap_err();

    let e2 = reopen(dir.path(), b"seed-crash3", fixed_clock(1_700_000_100));
    assert_eq!(e2.current_write_generation(), 2);
    assert_eq!(e2.key_info()["pending"], serde_json::Value::Null);
    assert!(e2.verify_audit().unwrap().ok);
}

// ---- 审计篡改检测 ----

#[test]
fn audit_chain_detects_modification_and_deletion() {
    let (dir, e) = test_engine("tamper", b"seed-tamper");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    e.redact("t", "a@b.com 邮件").unwrap();
    e.restore("t", &e.redact("t", "c@d.com").unwrap().accepted[0].token.clone().unwrap(), "用途")
        .unwrap();
    assert!(e.verify_audit().unwrap().ok);

    // 1) 改写某条记录的详情（无痕改写）必须被发现。
    let log = dir.path().join("audit.log");
    let content = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let target = lines[1].to_string();
    let tampered = target.replace("\"purpose\":\"用途\"", "\"purpose\":\"伪造\"");
    if tampered != target {
        let new_content = content.replacen(&target, &tampered, 1);
        std::fs::write(&log, &new_content).unwrap();
        let e2 = reopen(dir.path(), b"seed-tamper", fixed_clock(1_700_000_100));
        let report = e2.verify_audit().unwrap();
        assert!(!report.ok, "改写审计详情必须被检出");
        std::fs::write(&log, &content).unwrap();
    }

    // 2) 删除中间一条必须破坏 prev_hash 链。
    let mut kept: Vec<&str> = content.lines().collect();
    if kept.len() >= 3 {
        kept.remove(1);
        std::fs::write(&log, kept.join("\n") + "\n").unwrap();
        let e2 = reopen(dir.path(), b"seed-tamper", fixed_clock(1_700_000_200));
        assert!(!e2.verify_audit().unwrap().ok, "删除审计条目必须被检出");
        std::fs::write(&log, &content).unwrap();
    }

    // 恢复后再次校验通过。
    let e3 = reopen(dir.path(), b"seed-tamper", fixed_clock(1_700_000_300));
    assert!(e3.verify_audit().unwrap().ok);
}

#[test]
fn audit_records_both_success_and_failure() {
    let (_dir, e) = test_engine("auditlog", b"seed-audit");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, false)).unwrap();
    let tok = e.redact("t", "a@b.com").unwrap().accepted[0].token.clone().unwrap();
    e.restore("t", &tok, "合法用途").unwrap();
    let _ = e.restore("t", "garbage-token", "非法尝试").unwrap_err();

    let entries = e.read_audit(Some("t"), Some(100)).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|x| x.kind.as_str()).collect();
    assert!(kinds.contains(&"restore-ok"));
    assert!(kinds.contains(&"restore-denied"), "失败也必须追加审计");
    // 链式校验通过。
    assert!(e.verify_audit().unwrap().ok);
}

// ---- 导出不含原文映射 ----

#[test]
fn export_contains_only_redacted_text_rules_and_audit_summary() {
    let (_dir, e) = test_engine("export", b"seed-export");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    let secret = "绝密邮箱 alice@secret.example";
    e.redact("t", secret).unwrap();
    let bundle = e.export().unwrap();
    let serialized = serde_json::to_string(&bundle).unwrap();

    assert!(serialized.contains("alice@secret.example") == false, "导出不得包含原文");
    assert!(serialized.contains("original_cipher_hex") == false, "导出不得包含密文映射");
    assert!(serialized.contains("MTKN-G1-"), "导出应包含已脱敏文本");
    assert!(serialized.contains("rule_version"));
    assert!(serialized.contains("audit_summary"));
    assert_eq!(bundle.audit_summary.ok, true);

    // 已脱敏文本存在，规则元数据存在。
    let tenant = bundle.tenants.get("t").unwrap();
    assert_eq!(tenant.rule_metadata.rules.len(), 1);
    assert!(tenant.redactions[0].text.contains("MTKN-G1-"));
}

// ---- 规则校验与身份证内置规则 ----

#[test]
fn builtin_idcard_requires_valid_checksum() {
    let (_dir, e) = test_engine("idc", b"seed-idc");
    e.create_tenant("t").unwrap();
    e.upsert_rule(
        "t",
        RuleInput {
            id: None,
            name: "身份证".into(),
            kind: Some("idcard".into()),
            pattern: None,
            min: None,
            max: None,
            priority: Some(10),
            stable: Some(true),
            enabled: Some(true),
        },
    )
    .unwrap();
    // 校验位正确（公开示例号）。
    let ok = e.redact("t", "证件 11010519491231002X 完").unwrap();
    assert_eq!(ok.accepted.len(), 1);
    // 校验位错误的 18 位数字不应命中。
    let bad = e.redact("t", "证件 110105194912310020 完").unwrap();
    assert_eq!(bad.accepted.len(), 0);
}

#[test]
fn invalid_rule_input_is_rejected() {
    let (_dir, e) = test_engine("badrule", b"seed-badrule");
    e.create_tenant("t").unwrap();
    let bad_regex = e.upsert_rule("t", regex_rule("坏", "([0-9]+", 1, true));
    assert!(bad_regex.is_err());
    let bad_range = e.upsert_rule("t", range_rule("倒挂", 100, 1, 1, true));
    assert!(bad_range.is_err());
    let missing = e.upsert_rule(
        "t",
        RuleInput {
            id: None,
            name: "x".into(),
            kind: Some("regex".into()),
            pattern: None,
            min: None,
            max: None,
            priority: None,
            stable: None,
            enabled: None,
        },
    );
    assert!(missing.is_err());
}

#[test]
fn purpose_is_required_for_restore() {
    let (_dir, e) = test_engine("purpose", b"seed-purpose");
    e.create_tenant("t").unwrap();
    e.upsert_rule("t", email_rule(10, true)).unwrap();
    let tok = e.redact("t", "a@b.com").unwrap().accepted[0].token.clone().unwrap();
    assert!(e.restore("t", &tok, "   ").is_err());
    assert!(e.restore("t", &tok, "正常用途").is_ok());
}

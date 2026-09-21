const $ = (id) => document.getElementById(id);
let currentTenant = "";

function toast(msg, ok = true) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast " + (ok ? "ok" : "err");
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.className = "toast"), 4500);
}

async function api(path, body) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : {};
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data && data.error ? data.error.message : "请求失败 " + res.status;
    throw new Error(msg);
  }
  return data;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function fmtTime(unix) {
  return new Date(unix * 1000).toLocaleString("zh-CN", { hour12: false });
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "audit") loadAudit();
  };
});

$("rKind").onchange = () => {
  $("regexBox").style.display = $("rKind").value === "regex" ? "block" : "none";
  $("rangeBox").style.display = $("rKind").value === "range" ? "flex" : "none";
};

// ---------- 租户 ----------
$("tenantSelect").onchange = (e) => {
  currentTenant = e.target.value;
  loadRules();
  loadKeys();
};

async function loadTenants() {
  const data = await api("/api/tenants");
  const sel = $("tenantSelect");
  if (!data.tenants.includes(currentTenant)) currentTenant = data.tenants[0] || "";
  sel.innerHTML = data.tenants.map((t) => `<option ${t === currentTenant ? "selected" : ""}>${esc(t)}</option>`).join("");
  if (!data.tenants.length) {
    sel.innerHTML = '<option value="">（尚未创建租户）</option>';
  }
  if (currentTenant) {
    loadRules();
    loadKeys();
  }
}

(function addTenantUi() {
  const box = document.createElement("div");
  box.style.marginRight = "10px";
  box.innerHTML =
    '<input id="newTenant" placeholder="新租户标识" style="width:150px;display:inline-block"><button class="ghost" style="margin:0 0 0 6px;padding:7px 10px" id="btnNewTenant">登记</button>';
  document.querySelector("header").insertBefore(box, document.querySelector("header span"));
  document.getElementById("btnNewTenant").onclick = async () => {
    const t = document.getElementById("newTenant").value.trim();
    if (!t) return;
    try {
      await api("/api/tenants", { tenant: t });
      currentTenant = t;
      toast("租户已创建");
      loadTenants();
    } catch (e) { toast(e.message, false); }
  };
})();

// ---------- 规则 ----------
function ruleDetail(r) {
  if (r.type === "regex") return esc(r.detail.pattern || "");
  if (r.type === "range") return `[${r.detail.min}, ${r.detail.max}]`;
  return "内置";
}

async function loadRules() {
  if (!currentTenant) return;
  const meta = await api("/api/rules?tenant=" + encodeURIComponent(currentTenant));
  $("rVersion").textContent = "（版本 v" + meta.rule_version + "）";
  $("rulesBody").innerHTML = meta.rules
    .map(
      (r) => `<tr>
      <td>${esc(r.name)}</td>
      <td><span class="tag">${r.type}</span> ${ruleDetail(r)}</td>
      <td>${r.priority}</td>
      <td>${r.stable ? '<span class="pill ok">稳定</span>' : '<span class="pill warn">随机</span>'}</td>
      <td>${r.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill bad">停用</span>'}</td>
      <td>
        <button class="ghost" style="margin:0;padding:4px 8px" onclick="toggleRule('${esc(r.id)}',${!r.enabled})">${r.enabled ? "停用" : "启用"}</button>
        <button class="danger" style="margin:0 0 0 6px;padding:4px 8px" onclick="deleteRule('${esc(r.id)}')">删除</button>
      </td></tr>`
    )
    .join("");
}

window.toggleRule = async (id, enabled) => {
  try {
    await api("/api/rules/toggle", { tenant: currentTenant, rule_id: id, enabled });
    loadRules();
  } catch (e) { toast(e.message, false); }
};
window.deleteRule = async (id) => {
  if (!confirm("确认删除该规则？规则版本将递增。")) return;
  try {
    await api("/api/rules/delete", { tenant: currentTenant, rule_id: id });
    toast("已删除");
    loadRules();
  } catch (e) { toast(e.message, false); }
};

$("btnSaveRule").onclick = async () => {
  if (!currentTenant) return toast("请先创建并选择租户", false);
  const body = {
    tenant: currentTenant,
    name: $("rName").value.trim(),
    type: $("rKind").value,
    priority: parseInt($("rPrio").value || "0", 10),
    stable: $("rStable").value === "true",
  };
  if (body.type === "regex") body.pattern = $("rPattern").value;
  if (body.type === "range") {
    body.min = parseInt($("rMin").value, 10);
    body.max = parseInt($("rMax").value, 10);
  }
  try {
    await api("/api/rules", body);
    toast("规则已登记为新版本 v");
    $("rName").value = "";
    loadRules();
  } catch (e) { toast(e.message, false); }
};

// ---------- 脱敏 / 预览 ----------
function renderAdj(data) {
  $("outText").textContent = data.text;
  const lines = [];
  lines.push(`规则版本 v${data.rule_version} · 密钥 G${data.key_generation} · 受保护既有 token：${data.token_protected}`);
  for (const h of data.accepted) {
    lines.push(`✔ 接受 [${h.start}..${h.end}] ${h.rule_name}（优先级 ${h.priority}${h.stable ? "，稳定" : "，随机"}）=> ${h.token || "(预览占位)"}`);
  }
  for (const s of data.suppressed) {
    lines.push(`✖ 压下 [${s.start}..${s.end}] ${s.rule_name}：${s.reason}（胜出 ${s.by_rule_id}）`);
  }
  $("outDetail").textContent = lines.join("\n");
}

$("btnPreview").onclick = async () => {
  try { renderAdj(await api("/api/preview", { tenant: currentTenant, text: $("inText").value })); }
  catch (e) { toast(e.message, false); }
};
$("btnRedact").onclick = async () => {
  try {
    const d = await api("/api/redact", { tenant: currentTenant, text: $("inText").value });
    renderAdj(d);
    toast("脱敏完成：映射已加密保存");
  } catch (e) { toast(e.message, false); }
};

// ---------- 还原 ----------
$("btnRestore").onclick = async () => {
  try {
    const d = await api("/api/restore", {
      tenant: currentTenant,
      token: $("oneToken").value.trim(),
      purpose: $("onePurpose").value,
    });
    $("oneResult").className = "oktext";
    $("oneResult").textContent = "还原成功：" + d.original;
  } catch (e) {
    $("oneResult").className = "badtext";
    $("oneResult").textContent = "还原被拒绝：" + e.message;
  }
};
$("btnBatch").onclick = async () => {
  const items = $("batchText").value
    .split("\n").map((line) => line.trim()).filter(Boolean)
    .map((line) => {
      const idx = line.indexOf("\t") >= 0 ? line.indexOf("\t") : line.search(/\s{2,}/);
      const token = idx >= 0 ? line.slice(0, idx).trim() : line;
      const purpose = idx >= 0 ? line.slice(idx + 1).trim() : "批量还原";
      return { token, purpose };
    });
  try {
    const d = await api("/api/restore-batch", { tenant: currentTenant, items });
    $("batchResult").textContent = d.results
      .map((r) => `#${r.index} ${r.ok ? "✔ " + r.original : "✖ " + r.error}`)
      .join("\n");
  } catch (e) { toast(e.message, false); }
};

// ---------- 密钥 ----------
async function loadKeys() {
  try {
    const info = await api("/api/keys");
    $("genBadge").textContent = "密钥代次：G" + info.current_generation;
    $("keyInfo").innerHTML =
      `当前（读取/新写）代次：<b>G${info.current_generation}</b><br>` +
      `保留的历史代次：${info.retained_generations.map((g) => "G" + g).join("、")}<br>` +
      `未完成轮换：${info.pending ? "G" + info.pending : "无"}`;
  } catch (e) { /* ignore */ }
}
$("btnRotate").onclick = async () => {
  if (!confirm("轮换到新密钥代次？旧数据仍可用旧代次解开。")) return;
  try {
    const info = await api("/api/keys/rotate", {});
    toast("已轮换到 G" + info.current_generation);
    loadKeys();
  } catch (e) { toast(e.message, false); }
};

// ---------- 审计 ----------
$("btnVerify").onclick = async () => {
  const s = await api("/api/audit/verify");
  $("verifyBox").innerHTML = s.ok
    ? `<span class="pill ok">链完整</span> 共 ${s.entries} 条，末条 #${s.last_seq}，链头 <span class="tag">${esc(s.last_hash.slice(0, 16))}…</span>`
    : `<span class="pill bad">检测到篡改/断裂</span> ${esc(s.error || "")}`;
};
$("btnReloadAudit").onclick = loadAudit;
async function loadAudit() {
  const data = await api("/api/audit?limit=100");
  $("auditBody").innerHTML = data.entries
    .map(
      (e) => `<tr>
      <td>${e.seq}</td><td>${fmtTime(e.ts_unix)}</td>
      <td>${esc(e.tenant || "（全局）")}</td>
      <td><span class="tag">${esc(e.kind)}</span></td>
      <td><span class="tag">${esc(e.entry_hash.slice(0, 12))}</span></td>
      <td><pre style="max-height:80px;margin:0">${esc(JSON.stringify(e.details))}</pre></td></tr>`
    )
    .join("");
}

// ---------- 导出 ----------
$("btnExport").onclick = async () => {
  const bundle = await api("/api/export");
  $("exportOut").textContent = JSON.stringify(bundle, null, 2);
  toast("已生成导出（仅脱敏文本/规则元数据/审计摘要）");
};

loadTenants();
loadKeys();

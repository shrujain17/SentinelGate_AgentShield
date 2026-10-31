const $ = (selector) => document.querySelector(selector);

const examples = {
  read_email: { query: "project" },
  read_document: { document_id: "project-brief" },
  send_email: { to: "demo.client@example.test", subject: "Project update", body: "Synthetic demo email" },
  delete_file: { target: "draft.txt" },
  read_private_file: { path: "/private/keys.txt" },
  unknown_tool: { action: "do_something" },
};

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function showResult(response) {
  const { decision, execution } = response;
  $("#decisionEmpty").hidden = true;
  $("#decisionResult").hidden = false;
  const verdict = $("#verdict");
  verdict.textContent = decision.verdict;
  verdict.className = `verdict ${decision.verdict === "ALLOW" ? "allow" : decision.verdict === "DENY" ? "deny" : "approval"}`;
  $("#reason").textContent = decision.reason;
  const score = Math.round(Number(decision.risk_score || 0) * 100);
  $("#riskScore").textContent = `${score}%`;
  $("#riskBar").style.width = `${score}%`;
  $("#riskBar").style.background = score >= 80 ? "var(--red)" : score >= 40 ? "var(--amber)" : "var(--green)";
  const threats = $("#threats");
  threats.replaceChildren();
  const list = decision.threats_detected || [];
  if (!list.length) {
    const item = document.createElement("li"); item.textContent = "None"; item.style.color = "var(--green)"; threats.append(item);
  } else list.forEach((threat) => { const item = document.createElement("li"); item.textContent = threat; threats.append(item); });
  $("#execution").textContent = execution ? pretty(execution) : "No tool was executed.";
}

async function post(url, payload) {
  const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

async function refreshAudit() {
  const response = await fetch("/api/audit");
  const { events } = await response.json();
  const log = $("#auditLog"); log.replaceChildren();
  if (!events.length) { log.innerHTML = '<p class="empty-state">No decisions recorded yet.</p>'; return; }
  events.forEach((event) => {
    const row = document.createElement("div"); row.className = "audit-event";
    const detail = document.createElement("div");
    detail.innerHTML = `<strong>${event.tool_name}</strong><small>${event.reason}</small>`;
    const tag = document.createElement("span"); tag.className = `tag ${event.verdict}`; tag.textContent = event.verdict;
    row.append(detail, tag); log.append(row);
  });
}

$("#toolName").addEventListener("change", (event) => { $("#parameters").value = pretty(examples[event.target.value]); });
$("#submitRequest").addEventListener("click", async () => {
  try {
    const parameters = JSON.parse($("#parameters").value || "{}");
    const response = await post("/api/request", { tool_name: $("#toolName").value, parameters, context: $("#context").value, user_approved: $("#approval").checked });
    showResult(response); refreshAudit();
  } catch (error) { alert(error.message); }
});
$("#askAgent").addEventListener("click", async () => {
  try { const response = await post("/api/agent", { message: $("#agentMessage").value, user_approved: $("#approval").checked }); showResult(response); refreshAudit(); }
  catch (error) { alert(error.message); }
});
$("#refreshAudit").addEventListener("click", refreshAudit);
refreshAudit();

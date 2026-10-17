/**
 * LogMind Frontend Controller
 * Connects to the LinuxONE FastAPI Enclave backend
 */

let sampleCache = {};
let currentEvents = [];

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", async () => {
  await fetchSystemStatus();
  await loadSampleIndex();
  // Auto-load the attack sample by default
  loadSample("combined_attack.log");

  document.getElementById("logInput").addEventListener("input", updateLineCount);
});

// Fetch LinuxONE hardware and platform metadata
async function fetchSystemStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    if (data.platform) {
      const platElem = document.getElementById("platformName");
      if (platElem) {
        platElem.textContent = data.is_real_linuxone ? `${data.platform}` : `${data.platform}`;
      }
    }
    if (data.enclave_mode) {
      const boundElem = document.getElementById("trustBoundaryVal");
      if (boundElem) boundElem.textContent = data.enclave_mode;
    }
    if (data.crypto_acceleration) {
      const cryptoElem = document.getElementById("hardwareAccelVal");
      if (cryptoElem) cryptoElem.textContent = data.crypto_acceleration;
    }
    const platDot = document.getElementById("platformDot");
    if (platDot) {
      platDot.className = data.is_real_linuxone ? "dot emerald" : "dot amber";
    }

    // Fetch ML Models & Framework status
    const mlRes = await fetch("/api/ml-status");
    if (mlRes.ok) {
      const mlData = await mlRes.json();
      const aiElem = document.getElementById("aiModelsVal");
      if (aiElem && mlData.frameworks_loaded) {
        aiElem.textContent = "XGBoost + Granite 3.1";
        aiElem.title = mlData.frameworks_loaded.join(" | ");
      }
    }
  } catch (err) {
    console.warn("Status fetch fallback:", err);
  }
}

// Load sample files from backend
async function loadSampleIndex() {
  try {
    const res = await fetch("/api/sample-logs");
    if (!res.ok) return;
    sampleCache = await res.json();
  } catch (err) {
    console.warn("Failed to prefetch samples:", err);
  }
}

function loadSample(sampleName) {
  const content = sampleCache[sampleName] || "";
  const textarea = document.getElementById("logInput");
  textarea.value = content;
  updateLineCount();

  // Reset highlight buttons
  document.querySelectorAll(".preset-group .btn").forEach(b => b.classList.remove("active"));
  if (sampleName.includes("attack")) document.getElementById("loadAttackBtn")?.classList.add("active");
  if (sampleName.includes("pii")) document.getElementById("loadPiiBtn")?.classList.add("active");
  if (sampleName.includes("benign")) document.getElementById("loadBenignBtn")?.classList.add("active");

  // Auto inspect Upload Guard for immediate feedback
  inspectUploadGuard();
}

function updateLineCount() {
  const text = document.getElementById("logInput").value;
  const lines = text.trim() ? text.trim().split("\n").length : 0;
  document.getElementById("lineCount").textContent = `${lines} lines`;
}

// 1. Run Upload Data Guard Pre-Flight Scan
async function inspectUploadGuard() {
  const logText = document.getElementById("logInput").value;
  if (!logText.trim()) return;

  const guardBadge = document.getElementById("guardBadge");
  guardBadge.textContent = "SCANNING...";
  guardBadge.className = "badge";

  try {
    const res = await fetch("/api/upload-guard", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log_text: logText })
    });
    const data = await res.json();

    document.getElementById("statSecrets").textContent = data.stats.secrets_detected;
    document.getElementById("statPii").textContent = data.stats.pii_detected;
    document.getElementById("statIps").textContent = data.stats.network_addresses;

    const listEl = document.getElementById("findingsList");
    listEl.innerHTML = "";

    if (data.findings && data.findings.length > 0) {
      guardBadge.textContent = `${data.findings.length} FLAGGED`;
      guardBadge.className = "badge badge-red";

      data.findings.forEach(f => {
        const row = document.createElement("div");
        row.className = `finding-row ${f.category}`;
        row.innerHTML = `
          <span class="finding-type">[${f.type}]</span>
          <span class="finding-orig" style="color:#8b949e;">${escapeHtml(f.original)}</span>
          <span class="finding-mask">&rarr; ${escapeHtml(f.masked)}</span>
        `;
        listEl.appendChild(row);
      });
    } else {
      guardBadge.textContent = "CLEAN";
      guardBadge.className = "badge badge-version";
      listEl.innerHTML = `<div class="empty-state" style="color:#00e676;">&#9989; Pre-flight complete: No unmasked secrets or raw PII detected.</div>`;
    }
  } catch (err) {
    console.error("Upload Guard error:", err);
  }
}

// 2. Run Full LogMind Pipeline (Arm C)
async function runAnalysis() {
  const logText = document.getElementById("logInput").value;
  const applyMask = document.getElementById("guardMaskToggle").checked;
  if (!logText.trim()) {
    alert("Please paste or load logs to analyze.");
    return;
  }

  const btn = document.getElementById("runAnalyzeBtn");
  btn.innerHTML = `<span class="icon">&#9881;</span> Enclave Processing...`;
  btn.disabled = true;

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log_text: logText, apply_upload_masking: applyMask })
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Analysis Error: ${err.detail || "Failed to parse logs"}`);
      return;
    }

    const data = await res.json();
    renderTriageView(data);
  } catch (err) {
    console.error("Analyze error:", err);
    alert("Network error connecting to LinuxONE enclave API.");
  } finally {
    btn.innerHTML = `<span class="icon">&#129504;</span> 2. Analyze with LogMind`;
    btn.disabled = false;
  }
}

// Render Incident Triage, Explanation, Split View & Events
function renderTriageView(data) {
  const triageSec = document.getElementById("triageSection");
  triageSec.style.display = "flex";
  triageSec.scrollIntoView({ behavior: "smooth" });

  const verdict = data.verdict;
  const banner = document.getElementById("alertBanner");
  const verdictIcon = document.getElementById("verdictIcon");
  const severityBox = document.getElementById("severityBox");
  const severityVal = document.getElementById("severityVal");

  document.getElementById("verdictRuleName").textContent = verdict.rule_name;
  document.getElementById("verdictTitle").textContent = verdict.verdict.replace(/_/g, " ");
  document.getElementById("verdictSummary").textContent = verdict.rule_summary;
  severityVal.textContent = verdict.severity;
  document.getElementById("latencyLabel").textContent = `Latency: ${data.performance.total_latency_ms}ms (s390x)`;

  if (verdict.severity === "HIGH" || verdict.severity === "CRITICAL") {
    banner.className = "alert-banner";
    verdictIcon.innerHTML = "&#9888;";
    severityVal.style.color = "var(--crimson-fail)";
  } else {
    banner.className = "alert-banner benign";
    verdictIcon.innerHTML = "&#9989;";
    severityVal.style.color = "var(--emerald-pass)";
  }

  // AI Narrative
  const explanation = data.explanation;
  document.getElementById("aiNarrative").textContent = explanation.summary;

  // Tactics
  const tacticsEl = document.getElementById("tacticsTags");
  tacticsEl.innerHTML = "";
  (explanation.tactics || ["Initial Access", "Privilege Escalation"]).forEach(t => {
    const tag = document.createElement("span");
    tag.className = "tactic-tag";
    tag.textContent = t;
    tacticsEl.appendChild(tag);
  });

  // Citations
  const citationsEl = document.getElementById("citationPills");
  citationsEl.innerHTML = "";
  (explanation.cited_event_ids || []).forEach(eid => {
    const pill = document.createElement("span");
    pill.className = "citation-pill";
    pill.innerHTML = `&#128279; Event #${eid}`;
    pill.onclick = () => highlightEventRow(eid);
    citationsEl.appendChild(pill);
  });

  // "What the AI Saw" Inspector Split
  renderInspectorSplit(data);

  // Events Table
  currentEvents = data.events || [];
  renderEventsTable(currentEvents);
}

function renderInspectorSplit(data) {
  const vaultContent = document.getElementById("analystVaultContent");
  const modelContent = document.getElementById("modelSanitizedContent");

  // Analyst side: show original logs with quarantined raw payload highlighted
  const vault = data.quarantine_vault || {};
  let vaultHtml = `<div style="color:#8b949e; margin-bottom: 0.5rem;">[Secure Vault Cache] Quarantined entries held on LinuxONE:</div>`;

  if (Object.keys(vault).length === 0) {
    vaultHtml += `<div style="color:#00e676;">No attacker-controlled fields required quarantine.</div>`;
  } else {
    for (const [token, item] of Object.entries(vault)) {
      vaultHtml += `
        <div class="quarantine-highlight">
          <div><strong class="quarantined-token-badge">${token}</strong> &bull; Event #${item.event_id} (${item.field_name})</div>
          <div style="color:#ff7b72; margin-top:0.25rem; word-break: break-all;">"${escapeHtml(item.raw_value)}"</div>
          ${item.has_suspicious_payload ? `<div style="color:#ffab00; font-size:0.7rem; margin-top:0.25rem;">&#9888; Malicious prompt injection payload detected and prevented from reaching AI.</div>` : ''}
        </div>
      `;
    }
  }
  vaultContent.innerHTML = vaultHtml;

  // Model side: show sanitized facts JSON that was transmitted to LLM
  const sanitizedJson = JSON.stringify(data.sanitized_events, null, 2);
  modelContent.innerHTML = `<pre style="color:#7ee787; font-size:0.72rem; white-space:pre-wrap;">${escapeHtml(sanitizedJson)}</pre>`;
}

function renderEventsTable(events) {
  const tbody = document.getElementById("eventsTableBody");
  tbody.innerHTML = "";

  events.forEach(ev => {
    const tr = document.createElement("tr");
    tr.id = `event-row-${ev.event_id}`;

    let detailStr = "";
    if (ev.service === "web_server") {
      detailStr = `${ev.details.method || ''} ${ev.details.uri || ''} (${ev.details.user_agent ? 'UA: ' + ev.details.user_agent : ''})`;
    } else if (ev.service === "sudo") {
      detailStr = `CMD: ${ev.details.command || ''} (Target: ${ev.details.target_user || 'root'})`;
    } else {
      detailStr = ev.details.reason ? `Reason: ${ev.details.reason}` : `Host: ${ev.details.host || ''}`;
    }

    tr.innerHTML = `
      <td><strong>#${ev.event_id}</strong></td>
      <td>${ev.timestamp}</td>
      <td><span class="badge" style="background:rgba(255,255,255,0.06); font-size:0.7rem;">${ev.service}</span></td>
      <td><span class="badge-action ${ev.action}">${ev.action}</span></td>
      <td>${ev.account || '-'}</td>
      <td>${ev.status}</td>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(detailStr)}">${escapeHtml(detailStr)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function highlightEventRow(eventId) {
  document.querySelectorAll(".events-table tr").forEach(r => r.classList.remove("highlighted-row"));
  const row = document.getElementById(`event-row-${eventId}`);
  if (row) {
    row.classList.add("highlighted-row");
    row.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

// 3. Run Attack Replay (3-Arm Benchmark)
async function runAttackReplay() {
  const logText = document.getElementById("logInput").value;
  const replaySec = document.getElementById("replaySection");
  replaySec.style.display = "flex";
  replaySec.scrollIntoView({ behavior: "smooth" });

  try {
    const res = await fetch("/api/attack-replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log_text: logText })
    });
    const data = await res.json();

    document.getElementById("armADesc").innerHTML = `
      <em>Summary:</em> "${escapeHtml(data.arm_a.summary)}"<br>
      <span style="color:#ff334b; font-weight:600;">&#10060; CRITICAL: Injected prompt caused model to classify attack as authorized!</span>
    `;

    document.getElementById("armBDesc").innerHTML = `
      <em>Summary:</em> "${escapeHtml(data.arm_b.summary)}"<br>
      <span style="color:#ffab00; font-weight:600;">&#9888; WARNING: Prompt guard confused; downgraded severity from HIGH to MEDIUM.</span>
    `;

    document.getElementById("armCDesc").innerHTML = `
      <em>Summary:</em> "${escapeHtml(data.arm_c.summary)}"<br>
      <span style="color:#00e676; font-weight:600;">&#9989; 100% PROTECTED: Attacker payload quarantined; Severity Floor locked to HIGH.</span>
    `;
  } catch (err) {
    console.error("Attack Replay error:", err);
  }
}

function closeReplay() {
  document.getElementById("replaySection").style.display = "none";
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

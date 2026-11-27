/* CRIME404 Unified Frontend Controller */
let CASE_STATE = null;
let NETWORK_INSTANCE = null;
let SELECTED_FILE_CODE = null;

const $ = (id) => document.getElementById(id);
const esc = (str) =>
  String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

async function api(url, options = {}, allowFaceRetry = true) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  const headers = { ...(options.headers || {}) };
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(url, { cache: "no-store", credentials: "same-origin", ...options, headers });
  const responseText = await res.text();
  let data = {};
  try {
    data = responseText ? JSON.parse(responseText) : {};
  } catch {
    data = { error: responseText.slice(0, 300) };
  }
  if (res.status === 428 && data.face_verification_required && allowFaceRetry) {
    await captureFaceForAction(data.action);
    return api(url, options, false);
  }
  if (!res.ok) throw new Error(data.error || data.message || `Request failed (${res.status})`);
  return data;
}

async function captureFaceForAction(action) {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Face verification requires localhost or HTTPS and camera permission.");
  }
  const label = String(action || "sensitive_action").replaceAll("_", " ");
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: 640, height: 480 }, audio: false });

  return new Promise((resolve, reject) => {
    const overlay = document.createElement("div");
    overlay.style.cssText = "position:fixed;inset:0;background:rgba(25,35,30,0.48);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:100000;padding:16px;";
    overlay.innerHTML = `
      <div style="width:min(420px,100%);background:#F5F5EF;border:1px solid #829783;border-radius:16px;padding:20px;color:#202A27;font-family:system-ui,sans-serif;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#829783;font-weight:700;">Live Face Verification Required</div>
        <div style="font-size:15px;font-weight:700;margin:4px 0 10px;">Action: ${esc(label)}</div>
        <video id="modal-face-video" autoplay muted playsinline style="width:100%;height:260px;object-fit:cover;border-radius:10px;border:1px solid #C7D0C4;background:#000;transform:scaleX(-1);"></video>
        <div id="modal-face-msg" style="font-size:12px;color:#69766D;margin-top:8px;">Center your face in the frame, then click Capture &amp; Verify.</div>
        <div style="display:flex;gap:8px;margin-top:14px;">
          <button id="modal-face-verify-btn" class="btn" style="flex:1;justify-content:center;">Capture &amp; Verify Face</button>
          <button id="modal-face-cancel-btn" class="btn btn-ghost">Cancel</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const video = overlay.querySelector("#modal-face-video");
    const msgEl = overlay.querySelector("#modal-face-msg");
    const verifyBtn = overlay.querySelector("#modal-face-verify-btn");
    const cancelBtn = overlay.querySelector("#modal-face-cancel-btn");
    video.srcObject = stream;
    video.play().catch(() => {});

    const cleanup = () => {
      stream.getTracks().forEach((t) => t.stop());
      overlay.remove();
    };

    cancelBtn.onclick = () => {
      cleanup();
      reject(new Error("Face verification cancelled."));
    };

    verifyBtn.onclick = async () => {
      if (!video.videoWidth) {
        msgEl.textContent = "Camera is still warming up, please wait 1 second…";
        return;
      }
      verifyBtn.disabled = true;
      verifyBtn.textContent = "Verifying…";
      try {
        const canvas = document.createElement("canvas");
        canvas.width = video.videoWidth || 640;
        canvas.height = video.videoHeight || 480;
        canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
        await api(
          "/api/face/verify",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image: canvas.toDataURL("image/jpeg", 0.92), action }),
          },
          false
        );
        cleanup();
        resolve();
      } catch (err) {
        verifyBtn.disabled = false;
        verifyBtn.textContent = "Retry Capture & Verify";
        msgEl.style.color = "#A45F59";
        msgEl.textContent = err.message || "Verification failed; adjust lighting and retry.";
      }
    };
  });
}

window.toggleSecurityModal = function () {
  const modal = $("security-modal");
  if (!modal) return;
  modal.classList.toggle("hidden-view");
  if (!modal.classList.contains("hidden-view")) {
    loadUserProfile();
    loadCaseMembers();
    loadAuditLogs();
    loadOrgUsers();
    loadOrgInvites();
  }
};

window.toggleExportMenu = function () {
  const menu = $("exportMenu");
  if (menu) menu.classList.toggle("hidden-view");
};

window.toggleSeverityModal = function () {
  const modal = $("severity-modal");
  if (modal) modal.classList.toggle("hidden-view");
  renderSeverityModal();
};

window.toggleStandardsModal = function () {
  const modal = $("standards-modal");
  if (modal) modal.classList.toggle("hidden-view");
};

window.toggleConsoleDrawer = function () {
  const body = $("console-drawer-body");
  const btn = $("console-drawer-btn");
  if (!body) return;
  body.classList.toggle("hidden-view");
  if (btn) btn.textContent = body.classList.contains("hidden-view") ? "▲ Expand Engine Feed" : "▼ Collapse Engine Feed";
};

window.switchWorkspaceSubtab = function (subtab) {
  const gapsPane = $("subtab-gaps");
  const matrixPane = $("subtab-matrix");
  const gapsBtn = $("subtab-gaps-btn");
  const matrixBtn = $("subtab-matrix-btn");
  const isMatrix = subtab === "matrix";
  if (gapsPane) gapsPane.classList.toggle("hidden-view", isMatrix);
  if (matrixPane) matrixPane.classList.toggle("hidden-view", !isMatrix);
  if (gapsBtn) gapsBtn.classList.toggle("active", !isMatrix);
  if (matrixBtn) matrixBtn.classList.toggle("active", isMatrix);
  renderIsoMatrix();
};

window.openCaseModal = function () {
  if ($("case-form-error")) $("case-form-error").textContent = "";
  if ($("case-modal")) $("case-modal").classList.remove("hidden-view");
  if ($("new-case-title")) $("new-case-title").focus();
};

window.closeCaseModal = function () {
  if ($("case-modal")) $("case-modal").classList.add("hidden-view");
};

window.switchTab = function (tab) {
  const tabs = ["overview", "workspace", "files", "hypotheses", "compare", "custody", "cases", "profile"];
  tabs.forEach((t) => {
    const view = $(`view-${t}`);
    const nav = $(`nav-${t}`);
    if (view) view.classList.toggle("hidden-view", t !== tab);
    if (nav) nav.classList.toggle("active", t === tab);
  });
  if (tab === "overview") renderGraph();
  if (tab === "files") renderFilesViewer();
  if (tab === "compare") {
    renderCompareDropdowns();
    const items = (CASE_STATE?.evidence || []).filter((a) => !a.retired);
    if (items.length >= 2) runEvidenceComparison();
  }
  if (tab === "custody") {
    renderCustodyTable();
    renderActivityFeed();
  }
  if (tab === "profile") loadUserProfile();
};

async function fetchCaseState() {
  try {
    CASE_STATE = await api("/api/state");
    renderAll(false);
    await refreshCaseSelector();
    await loadUserProfile();
  } catch (err) {
    console.error("Failed to fetch state:", err);
    const title = $("header-case");
    if (title) title.textContent = "Unable to load case — refresh or sign in again";
  }
}

async function refreshCaseSelector() {
  const selector = $("header-case-select");
  if (!selector) return;
  try {
    const data = await api("/api/cases");
    const activeId = CASE_STATE?.active_case?.id;
    selector.innerHTML =
      (data.cases || [])
        .map(
          (c) =>
            `<option value="${Number(c.id)}" ${Number(c.id) === Number(activeId) ? "selected" : ""}>${esc(c.case_code)} · ${esc(c.title)}</option>`
        )
        .join("") || '<option value="">No cases available</option>';
  } catch (err) {
    selector.innerHTML = '<option value="">Unable to load cases</option>';
  }
}

function renderAll(showReassessment = false) {
  if (!CASE_STATE) return;

  const ac = CASE_STATE.active_case || {};
  const metrics = CASE_STATE.metrics || {};
  const headerCase = $("header-case");
  if (headerCase) headerCase.textContent = `${ac.case_code || "#404"} · ${ac.title || "Investigation Workspace"}`;

  const selector = $("header-case-select");
  if (selector) {
    const cases = CASE_STATE.cases || [];
    selector.innerHTML = cases.length
      ? cases
          .map(
            (c) =>
              `<option value="${Number(c.id)}" ${Number(c.id) === Number(ac.id) ? "selected" : ""}>${esc(c.case_code)} · ${esc(c.title)}</option>`
          )
          .join("")
      : '<option value="">No cases available</option>';
    selector.disabled = false;
  }

  if ($("overview-title")) $("overview-title").textContent = ac.title || "Case Overview";
  if ($("overview-code")) $("overview-code").textContent = ac.case_code || "#404";
  if ($("overview-description")) $("overview-description").textContent = ac.description || "No incident description provided.";
  if ($("case-status")) $("case-status").value = ac.status || "Active";

  const score = metrics.severity_score ?? 0;
  const label = metrics.severity_label || "LOW";
  if ($("hdr-severity-score")) $("hdr-severity-score").textContent = `${score}/100 (${label})`;
  if ($("overview-risk")) $("overview-risk").textContent = `${score}/100`;
  if ($("overview-risk-label")) $("overview-risk-label").textContent = label;

  const evList = CASE_STATE.evidence || [];
  const activeEvList = evList.filter((a) => !a.retired);
  const hyps = CASE_STATE.structured_hypotheses || [];
  const gaps = CASE_STATE.structured_gaps || [];

  if ($("overview-evidence")) $("overview-evidence").textContent = activeEvList.length;
  if ($("overview-events")) $("overview-events").textContent = metrics.total_events ?? 0;
  if ($("overview-gaps")) $("overview-gaps").textContent = gaps.length;
  if ($("evidence-count")) $("evidence-count").textContent = `${activeEvList.length} file${activeEvList.length === 1 ? "" : "s"}`;
  if ($("badge-files")) $("badge-files").textContent = evList.length;
  if ($("badge-hyps")) $("badge-hyps").textContent = hyps.length;
  if ($("badge-custody")) $("badge-custody").textContent = evList.length;

  if (showReassessment && CASE_STATE.reassessments && CASE_STATE.reassessments.length) {
    const latest = CASE_STATE.reassessments[0];
    if ($("reassessment-text")) $("reassessment-text").textContent = `${latest.trigger} — ${latest.diff}`;
    if ($("reassessment-banner")) $("reassessment-banner").classList.remove("hidden-view");
  }

  renderOverviewFindings();
  renderEvidenceList();
  renderFilesViewer();
  renderGaps();
  renderIsoMatrix();
  renderTimeline();
  renderHypothesesAndFindings();
  renderCompareDropdowns();
  renderCustodyTable();
  renderCasesGrid();
  renderSeverityModal();
  renderActivityFeed();
  renderGraph();
}

function renderOverviewFindings() {
  const el = $("overview-findings-list");
  if (!el) return;
  const findings = CASE_STATE.structured_findings || [];
  const gaps = CASE_STATE.structured_gaps || [];
  const combined = [
    ...gaps.map((g) => `<div class="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30"><div class="font-semibold text-rose-300">${esc(g.gap_type)}: ${esc(g.title)}</div><div class="text-[11px] text-slate-300 mt-1">${esc(g.explanation)}</div></div>`),
    ...findings.map((f) => `<div class="p-3 rounded-lg bg-slate-900 border border-slate-800"><div class="flex justify-between"><span class="font-semibold text-sky-300">${esc(f.title)}</span><span class="pill text-[10px]">${esc(f.mitre_id)}</span></div><div class="text-[11px] text-slate-300 mt-1">${esc(f.detail)}</div></div>`),
  ];
  el.innerHTML = combined.length
    ? combined.join("")
    : '<p class="text-slate-500">No findings generated yet. Upload log artifacts to begin.</p>';
}

function renderEvidenceList() {
  const el = $("evidence-list");
  if (!el) return;
  const items = (CASE_STATE.evidence || []).filter((a) => !a.retired);
  if (!items.length) {
    el.innerHTML = '<p class="text-xs text-slate-500">No active artifacts uploaded yet.</p>';
    return;
  }
  el.innerHTML = items
    .map(
      (a) => `
    <div class="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-2">
      <div class="min-w-0">
        <div class="flex items-center gap-2">
          <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300">${esc(a.artifact_code || a.id)}</span>
          <span class="text-xs font-semibold text-slate-100 truncate">${esc(a.name)}</span>
        </div>
        <div class="text-[11px] text-slate-400 mt-1">${a.records} records • SHA-256: <span class="font-mono">${esc((a.sha256 || "").slice(0, 12))}...</span></div>
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <button onclick="openUploadedFile('${esc(a.artifact_code || a.id)}')" class="px-2 py-1 rounded bg-sky-950/70 hover:bg-sky-800 text-sky-300 text-[11px] font-semibold">View</button>
        <button data-action="delete-evidence" data-code="${esc(a.artifact_code || a.id)}" data-name="${esc(a.name)}" title="Retire Artifact (Face Verified)" class="px-2 py-1 rounded bg-rose-950/60 hover:bg-rose-800 text-rose-300 text-xs font-bold">✕</button>
      </div>
    </div>`
    )
    .join("");
}

function renderFilesViewer() {
  const listEl = $("files-view-list");
  const countEl = $("files-view-count");
  if (!listEl) return;
  const items = CASE_STATE?.evidence || [];
  if (countEl) countEl.textContent = `${items.length} file${items.length === 1 ? "" : "s"}`;
  if (!items.length) {
    listEl.innerHTML = '<p class="text-xs text-slate-500">No uploaded files in this case yet.</p>';
    return;
  }
  listEl.innerHTML = items
    .map((a) => {
      const code = a.artifact_code || a.id;
      const selected = code === SELECTED_FILE_CODE;
      return `
      <div onclick="openUploadedFile('${esc(code)}', false)" class="p-3 rounded-xl border cursor-pointer transition ${
        selected ? "bg-sky-950/30 border-sky-500" : "bg-slate-950 border-slate-800 hover:border-slate-600"
      }">
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-[10px] text-sky-300">${esc(code)}</span>
          <span class="pill text-[10px] ${a.retired ? "text-amber-300 border-amber-500/40" : "text-emerald-300 border-emerald-500/40"}">${esc(
        a.retired ? "Retired" : a.status || "Verified"
      )}</span>
        </div>
        <div class="text-xs font-semibold text-white truncate mt-1">${esc(a.name)}</div>
        <div class="text-[11px] text-slate-400 mt-1">${a.records} records · ${Number(a.file_size || 0).toLocaleString()} bytes</div>
      </div>`;
    })
    .join("");
}

window.openUploadedFile = async function (code, switchToFilesTab = true) {
  SELECTED_FILE_CODE = code;
  if (switchToFilesTab) switchTab("files");
  renderFilesViewer();
  const contentEl = $("file-viewer-content");
  const metaEl = $("file-viewer-meta");
  const actionsEl = $("file-viewer-actions");
  if (contentEl) contentEl.textContent = `Verifying SHA-256 digest and decrypting ${code}…`;
  try {
    const data = await api(`/api/evidence/${encodeURIComponent(code)}/content`);
    if ($("file-viewer-code")) $("file-viewer-code").textContent = `${data.artifact_code} · ${data.type} · ${data.integrity_message}`;
    if ($("file-viewer-name")) $("file-viewer-name").textContent = data.name;
    if (metaEl) {
      metaEl.classList.remove("hidden-view");
      metaEl.innerHTML = `
        <div><span class="text-slate-400">SHA-256:</span> <span class="font-mono text-emerald-300 break-all">${esc(data.sha256)}</span></div>
        <div><span class="text-slate-400">Coverage Window:</span> <span class="text-slate-200">${esc(data.coverage_window)}</span></div>
        <div><span class="text-slate-400">Ingested:</span> <span class="text-slate-200">${esc(data.uploaded_by)} at ${esc(data.uploaded_at)}</span></div>
      `;
    }
    if (actionsEl) {
      actionsEl.innerHTML = `<button data-action="delete-evidence" data-code="${esc(data.artifact_code)}" data-name="${esc(
        data.name
      )}" class="btn btn-ghost !py-1 !px-2.5 !text-[11px] text-rose-300 border-rose-500/40">Retire File (Face Verified)</button>`;
    }
    if (contentEl) contentEl.textContent = data.content || "(Empty file)";
  } catch (err) {
    if (contentEl) contentEl.textContent = `Unable to inspect file: ${err.message}`;
  }
};

function renderGaps() {
  const el = $("gaps-list");
  if (!el) return;
  const gaps = CASE_STATE.structured_gaps || [];
  if (!gaps.length) {
    el.innerHTML = '<p class="text-xs text-slate-500">No timeline gaps or contradictions detected.</p>';
    return;
  }
  el.innerHTML = gaps
    .map(
      (g) => `
    <div class="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/30">
      <div class="font-semibold text-xs text-rose-300">${esc(g.gap_type)}: ${esc(g.title)}</div>
      <div class="text-[11px] text-slate-300 mt-0.5">${esc(g.explanation)}</div>
      <div class="text-[10px] text-amber-300 mt-1">Recommended Acquisition: ${esc(g.recommended_source)}</div>
    </div>`
    )
    .join("");
}

function renderIsoMatrix() {
  if (!CASE_STATE) return;
  const facts = (CASE_STATE.timeline || []).filter((t) => t.type === "fact");
  const hyps = CASE_STATE.structured_hypotheses || [];
  const gaps = CASE_STATE.structured_gaps || [];

  if ($("matrix-facts-summary")) {
    $("matrix-facts-summary").textContent = `${facts.length} objective log event(s) directly corroborated in ingested artifacts.`;
  }
  if ($("matrix-facts-list")) {
    $("matrix-facts-list").innerHTML = facts.length
      ? facts.slice(0, 12).map((f) => `<li><span class="font-mono text-sky-300">[${esc(f.timestamp)}]</span> ${esc(f.description)}</li>`).join("")
      : "<li>No logged facts ingested yet.</li>";
  }

  if ($("matrix-hyps-summary")) {
    $("matrix-hyps-summary").textContent = `${hyps.length} analytical hypothesis scenario(s) evaluated against supporting and contradicting telemetry.`;
  }
  if ($("matrix-hyps-list")) {
    $("matrix-hyps-list").innerHTML = hyps.length
      ? hyps.map((h) => `<li><strong>${esc(h.title)}</strong> (${Number(h.plausibility) || 0}% heuristic · ${esc(h.mitre_id)})</li>`).join("")
      : "<li>No hypotheses evaluated yet.</li>";
  }

  if ($("matrix-gaps-summary")) {
    $("matrix-gaps-summary").textContent = `${gaps.length} blind spot(s) or cross-source contradiction(s) requiring corroboration.`;
  }
  if ($("matrix-gaps-list")) {
    $("matrix-gaps-list").innerHTML = gaps.length
      ? gaps.map((g) => `<li><strong>${esc(g.gap_type)}:</strong> ${esc(g.title)}</li>`).join("")
      : "<li>No unresolved blind spots or contradictions.</li>";
  }
}

window.renderTimeline = function () {
  const el = $("timeline-container") || $("timeline-list");
  if (!el || !CASE_STATE) return;
  const q = ($("timeline-search")?.value || "").toLowerCase().trim();
  const cat = $("timeline-filter")?.value || "all";

  let items = CASE_STATE.timeline || [];
  if (cat !== "all") items = items.filter((t) => t.type === cat);
  if (q) {
    items = items.filter(
      (t) =>
        (t.description || "").toLowerCase().includes(q) ||
        (t.timestamp || "").toLowerCase().includes(q) ||
        (t.source || "").toLowerCase().includes(q)
    );
  }

  if (!items.length) {
    el.innerHTML = '<p class="text-xs text-slate-500">No matching timeline events.</p>';
    return;
  }

  el.innerHTML = items
    .map((t) => {
      const badgeColor =
        t.type === "gap"
          ? "border-rose-500/40 bg-rose-950/30 text-rose-300"
          : t.type === "hypothesis"
          ? "border-amber-500/40 bg-amber-950/30 text-amber-300"
          : "border-emerald-500/40 bg-emerald-950/30 text-emerald-300";
      const noteHtml = t.db_id
        ? `<div class="mt-2 flex gap-2">
            <input id="note-input-${t.db_id}" value="${esc(t.note)}" placeholder="Add investigator note..." class="field !py-1 !text-[11px]">
            <button onclick="saveEventNote(${t.db_id})" class="btn !py-1 !px-2.5 !text-[11px]">Save</button>
           </div>`
        : "";
      return `
      <div class="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="font-mono text-[11px] text-sky-300">${esc(t.timestamp)}</span>
          <div class="flex items-center gap-2">
            <span class="pill ${badgeColor}">${esc(t.confidence)}</span>
            <span class="text-[10px] text-slate-400">${esc(t.source)}</span>
          </div>
        </div>
        <div class="text-xs font-semibold text-slate-100 mt-1">${esc(t.title)}</div>
        <div class="text-xs text-slate-300 mt-0.5">${esc(t.description)}</div>
        ${noteHtml}
      </div>`;
    })
    .join("");
};

function renderHypothesesAndFindings() {
  const fullHypothesesEl = $("full-hypotheses-grid");
  const overviewHypothesesEl = $("overview-hypotheses");
  const fullFindingsEl = $("full-findings-list");

  const hypotheses = CASE_STATE?.structured_hypotheses || [];
  const findings = CASE_STATE?.structured_findings || [];

  const hypothesisCards = hypotheses
    .map(
      (h) => `
    <div class="panel p-4 space-y-2">
      <div class="flex items-center justify-between gap-2">
        <div class="font-semibold text-sm text-white">${esc(h.title)}</div>
        <span class="pill bg-sky-500/15 border-sky-500/40 text-sky-300 font-bold">${Number(h.plausibility) || 0}% Heuristic Score</span>
      </div>
      <div class="text-[11px] text-amber-300 font-mono">MITRE ATT&CK: ${esc(h.mitre_id || "Not mapped")}</div>
      <p class="text-xs text-slate-300">${esc(h.summary || "No hypothesis summary is available yet.")}</p>
      <div class="text-[11px] text-emerald-300"><strong>Supporting evidence:</strong> ${esc((h.supporting || []).join(" | ") || "None recorded")}</div>
      <div class="text-[11px] text-rose-300"><strong>Contradicting evidence:</strong> ${esc((h.contradicting || []).join(" | ") || "None recorded")}</div>
      <div class="text-[11px] text-slate-400"><strong>Questions to resolve:</strong> ${esc((h.questions || []).join(" | ") || "None recorded")}</div>
      <div class="text-[11px] text-slate-400"><strong>Recommended evidence:</strong> ${esc((h.required_evidence || []).join(", ") || "Not specified")}</div>
    </div>
  `
    )
    .join("");

  if (fullHypothesesEl) {
    fullHypothesesEl.innerHTML =
      hypothesisCards ||
      '<div class="panel p-4 text-xs text-slate-400">No hypotheses generated for this case yet. Upload and analyze evidence to generate case-specific hypotheses.</div>';
  }

  if (overviewHypothesesEl) {
    overviewHypothesesEl.innerHTML =
      hypothesisCards || '<p class="text-xs text-slate-500">No hypotheses generated yet. Upload evidence to begin analysis.</p>';
  }

  if (fullFindingsEl) {
    fullFindingsEl.innerHTML = findings.length
      ? findings
          .map(
            (f) => `
          <div class="panel p-4 space-y-1">
            <div class="flex items-center justify-between gap-2">
              <span class="font-semibold text-xs text-slate-100">${esc(f.title)}</span>
              <span class="pill text-[10px] text-emerald-300 border-emerald-500/40">${esc(f.confidence_tier || "Unrated")}</span>
            </div>
            <div class="text-xs text-slate-300">${esc(f.detail || "")}</div>
            <div class="text-[11px] text-slate-400">${esc(f.confidence_reason || "")}</div>
          </div>
        `
          )
          .join("")
      : '<p class="text-xs text-slate-500">No traceable findings recorded yet. Upload evidence to begin analysis.</p>';
  }
}

function renderCompareDropdowns() {
  const selA = $("compare-a");
  const selB = $("compare-b");
  if (!selA || !selB) return;
  const items = (CASE_STATE.evidence || []).filter((a) => !a.retired);
  const opts = items.map((a) => `<option value="${esc(a.artifact_code)}">${esc(a.artifact_code)} — ${esc(a.name)}</option>`).join("");
  selA.innerHTML = opts || '<option value="">No active artifacts</option>';
  selB.innerHTML = opts || '<option value="">No active artifacts</option>';
  if (items.length >= 2) selB.selectedIndex = 1;
}

window.runEvidenceComparison = async function () {
  const a = $("compare-a")?.value;
  const b = $("compare-b")?.value;
  const out = $("compare-results");
  if (!out) return;
  if (!a || !b) {
    out.innerHTML = '<p class="text-amber-400">Upload at least two artifacts to run cross-source comparison.</p>';
    return;
  }
  if (a === b) {
    out.innerHTML = '<p class="text-amber-400">Please select two different uploaded artifacts to compare.</p>';
    return;
  }
  out.innerHTML = '<p class="text-sky-300">Correlating entities and UTC windows across selected artifacts…</p>';
  try {
    const d = await api(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    out.innerHTML = `
      <div class="space-y-4">
        <div class="grid md:grid-cols-3 gap-3 text-xs">
          <div class="p-3 rounded-lg bg-sky-950/40 border border-sky-500/30">
            <div class="font-bold text-sky-300">Shared Correlated Entities</div>
            <div class="mt-1 text-slate-200 font-mono">${esc((d.shared_entities || []).join(", ") || "None")}</div>
          </div>
          <div class="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div class="font-bold text-emerald-300">Unique to ${esc(d.artifact_a.name)}</div>
            <div class="mt-1 text-slate-300 font-mono">${esc((d.only_in_a || []).join(", ") || "None")}</div>
          </div>
          <div class="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div class="font-bold text-amber-300">Unique to ${esc(d.artifact_b.name)}</div>
            <div class="mt-1 text-slate-300 font-mono">${esc((d.only_in_b || []).join(", ") || "None")}</div>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div class="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div class="font-bold text-white mb-1">${esc(d.artifact_a.name)} (${d.artifact_a.count} events)</div>
            <div class="text-[11px] text-sky-300 mb-2">UTC Window: ${esc(d.artifact_a.coverage)}</div>
            <ul class="list-disc pl-4 space-y-1 text-[11px] text-slate-300 max-h-64 overflow-y-auto">${(d.events_a || [])
              .map((x) => `<li>${esc(x)}</li>`)
              .join("")}</ul>
          </div>
          <div class="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div class="font-bold text-white mb-1">${esc(d.artifact_b.name)} (${d.artifact_b.count} events)</div>
            <div class="text-[11px] text-sky-300 mb-2">UTC Window: ${esc(d.artifact_b.coverage)}</div>
            <ul class="list-disc pl-4 space-y-1 text-[11px] text-slate-300 max-h-64 overflow-y-auto">${(d.events_b || [])
              .map((x) => `<li>${esc(x)}</li>`)
              .join("")}</ul>
          </div>
        </div>
      </div>`;
  } catch (err) {
    out.innerHTML = `<p class="text-rose-400">${esc(err.message)}</p>`;
  }
};

function renderCustodyTable() {
  const tbody = $("custody-table-body");
  if (!tbody) return;
  const items = CASE_STATE.custody || CASE_STATE.evidence || [];
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="py-4 text-center text-slate-500">No artifacts in custody vault yet. Ingest evidence to record SHA-256 provenance.</td></tr>';
    return;
  }
  tbody.innerHTML = items
    .map(
      (a) => `
    <tr class="hover:bg-slate-900/60">
      <td class="py-2.5 pr-4 font-mono text-sky-300">${esc(a.artifact_code || a.id)}</td>
      <td class="py-2.5 pr-4 font-semibold text-slate-100">${esc(a.name)} <span class="text-[10px] text-slate-400">(${esc(a.type || "LOG")})</span></td>
      <td class="py-2.5 pr-4 font-mono text-[11px] text-slate-300 break-all">${esc(a.sha256 || a.sha256_hash || "N/A")}</td>
      <td class="py-2.5 pr-4 text-slate-300">${esc(a.coverage || "N/A")}</td>
      <td class="py-2.5 pr-4 text-slate-400">${esc(a.ingested_by || a.uploaded_by)} • ${esc(a.ingested_at || a.timestamp)}</td>
      <td class="py-2.5 pr-4"><span class="pill ${
        a.retired ? "bg-amber-500/15 border-amber-500/40 text-amber-300" : "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
      }">${esc(a.status || "Verified")}</span></td>
      <td class="py-2.5 text-right whitespace-nowrap">
        <button onclick="openUploadedFile('${esc(a.artifact_code || a.id)}')" class="px-2 py-1 rounded bg-sky-950 hover:bg-sky-800 text-sky-200 text-[11px] mr-1">View</button>
        ${
          a.retired
            ? ""
            : `<button data-action="delete-evidence" data-code="${esc(a.artifact_code || a.id)}" data-name="${esc(
                a.name
              )}" class="px-2 py-1 rounded bg-rose-950 hover:bg-rose-800 text-rose-200 text-[11px]">Retire</button>`
        }
      </td>
    </tr>`
    )
    .join("");
}

window.verifyVaultIntegrity = async function () {
  const banner = $("custody-verify-banner");
  try {
    const res = await api("/api/custody/verify");
    if (banner) {
      banner.textContent = res.verified
        ? `✓ NIST SP 800-86 Verification Passed: All ${res.artifacts.length} artifact(s) in this case matched their immutable SHA-256 digests.`
        : "⚠ Warning: One or more artifacts failed SHA-256 hash verification!";
      banner.classList.remove("hidden-view");
    }
  } catch (err) {
    alert(err.message);
  }
};

function renderCasesGrid() {
  const grid = $("cases-grid");
  if (!grid) return;
  const allCases = CASE_STATE.cases || [];
  const activeId = CASE_STATE.active_case?.id;
  const query = ($("case-search")?.value || "").trim().toLowerCase();
  const status = $("case-status-filter")?.value || "all";
  const cases = allCases.filter((c) => {
    const haystack = `${c.case_code || ""} ${c.title || ""} ${c.description || ""}`.toLowerCase();
    return (!query || haystack.includes(query)) && (status === "all" || (c.status || "Active") === status);
  });
  if ($("case-total")) $("case-total").textContent = allCases.length;
  if ($("case-active")) $("case-active").textContent = allCases.filter((c) => !["Archived", "Resolved"].includes(c.status)).length;
  if ($("case-closed")) $("case-closed").textContent = allCases.filter((c) => ["Archived", "Resolved"].includes(c.status)).length;
  grid.innerHTML = cases.length
    ? cases
        .map(
          (c) => `
    <div class="panel p-4 flex flex-col justify-between gap-3 ${c.id === activeId ? "border-sky-500" : ""}">
      <div>
        <div class="flex items-center justify-between">
          <span class="font-mono text-xs text-sky-400">${esc(c.case_code)}</span>
          <span class="pill text-[10px]">${Number(c.artifact_count || 0)} Artifacts · ${esc(c.status || "Active")}</span>
        </div>
        <h3 class="font-bold text-sm text-white mt-1">${esc(c.title)}</h3>
        <p class="text-xs text-slate-400 mt-1">${esc(c.description || "No case description provided")}</p>
      </div>
      <div class="flex items-center justify-between pt-2 border-t border-slate-800">
        <button onclick="switchCase(${Number(c.id)})" class="btn !py-1.5 !px-3">${Number(c.id) === Number(activeId) ? "Active Workspace" : "Open Case"}</button>
        <button data-action="delete-case" data-case-id="${Number(c.id)}" data-title="${esc(c.title)}" class="btn btn-ghost !py-1.5 !px-3 text-rose-300 border-rose-500/30">Delete Case</button>
      </div>
    </div>`
        )
        .join("")
    : '<p class="text-sm text-slate-500">No cases match this search or status filter.</p>';
}
window.renderCases = renderCasesGrid;

function renderSeverityModal() {
  const body = $("severity-breakdown-list");
  if (!body || !CASE_STATE) return;
  const m = CASE_STATE.metrics || {};
  const rows = (m.severity_breakdown || [])
    .map(
      (r) => `
      <div class="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
        <div class="flex justify-between items-center">
          <span class="font-semibold text-slate-100">${esc(r.factor)}</span>
          <span class="font-bold text-amber-300">+${r.points} pts</span>
        </div>
        <p class="text-[11px] text-slate-400">${esc(r.reason || "")}</p>
      </div>`
    )
    .join("");
  body.innerHTML = `
    <div class="p-3 rounded-xl bg-sky-950/30 border border-sky-500/30 flex items-center justify-between">
      <div>
        <div class="text-sm font-bold text-white">Total Risk Score: ${m.severity_score ?? 0}/100 (${esc(m.severity_label || "LOW")})</div>
        <div class="text-[11px] text-slate-400 mt-0.5">${esc(m.severity_method || "")}</div>
      </div>
    </div>
    <div class="mt-2 space-y-2">${
      rows ||
      "<div class='p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-300'>Score is 0/100 (LOW) because no privilege escalation, repeated failed logins, external exfiltration, or timeline contradictions have been detected in the active evidence yet.</div>"
    }</div>`;
}

function renderActivityFeed() {
  const el = $("activity-feed");
  const drawer = $("console-drawer-body");
  const logs = (CASE_STATE.activity_logs || []).slice().reverse();
  const html = logs.length
    ? logs.map((l) => `<div class="border-b border-slate-800 pb-1.5">${esc(l)}</div>`).join("")
    : '<p class="text-slate-500">No custody or engine activity recorded yet.</p>';
  if (el) el.innerHTML = html;
  if (drawer) drawer.innerHTML = html;
}

function renderGraph() {
  const container = $("graph-canvas");
  if (!container || typeof vis === "undefined" || !CASE_STATE?.graph) return;
  const colorMap = { ip: "#829783", user: "#6F9274", file: "#B18A4B", process: "#A9828A" };
  const nodes = new vis.DataSet(
    (CASE_STATE.graph.nodes || []).map((n) => ({
      id: n.id,
      label: n.label,
      color: { background: colorMap[n.type] || "#829783", border: "#F5F5EF" },
      font: { color: "#f8fafc", size: 12 },
      shape: "dot",
      size: 16,
    }))
  );
  const edges = new vis.DataSet(
    (CASE_STATE.graph.links || []).map((l) => ({
      from: l.source,
      to: l.target,
      label: l.label,
      font: { color: "#69766D", size: 10, strokeWidth: 0 },
      color: { color: "#C7D0C4" },
      arrows: "to",
    }))
  );
  if (NETWORK_INSTANCE) {
    NETWORK_INSTANCE.destroy();
    NETWORK_INSTANCE = null;
  }
  NETWORK_INSTANCE = new vis.Network(container, { nodes, edges }, { physics: { stabilization: true } });
}

// Mutations & Actions
window.submitNewCase = async function (event) {
  event.preventDefault();
  const title = $("new-case-title")?.value.trim();
  const description = $("new-case-description")?.value.trim();
  const errorEl = $("case-form-error");
  const submit = $("case-form")?.querySelector('button[type="submit"]');
  if (!title) {
    if (errorEl) errorEl.textContent = "Enter a case title.";
    return;
  }
  if (submit) {
    submit.disabled = true;
    submit.textContent = "Creating…";
  }
  if (errorEl) errorEl.textContent = "Saving case…";
  try {
    const data = await api("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, description }),
    });
    if (!data.state?.active_case) throw new Error("The server did not return the newly created case.");
    CASE_STATE = data.state;
    $("case-form")?.reset();
    closeCaseModal();
    renderAll(false);
    switchTab("overview");
  } catch (err) {
    if (errorEl) errorEl.textContent = err.message;
  } finally {
    if (submit) {
      submit.disabled = false;
      submit.textContent = "Create Case & Open";
    }
  }
};

window.switchCase = async function (caseId) {
  const selector = $("header-case-select");
  if (!caseId) return;
  if (selector) selector.disabled = true;
  try {
    const data = await api(`/api/cases/switch/${Number(caseId)}`, { method: "POST" });
    if (!data.state?.active_case) throw new Error("The server did not return the selected case workspace.");
    CASE_STATE = data.state;
    SELECTED_FILE_CODE = null;
    renderAll(false);
    switchTab("overview");
    if (selector) selector.value = String(CASE_STATE.active_case.id);
  } catch (err) {
    alert(`Could not switch cases: ${err.message}`);
    await fetchCaseState();
  } finally {
    if (selector) selector.disabled = false;
  }
};

window.updateCaseStatus = async function (status) {
  const active = CASE_STATE?.active_case;
  if (!active) return;
  try {
    const data = await api(`/api/cases/${active.id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    CASE_STATE = data.state;
    renderAll(false);
  } catch (err) {
    alert(err.message);
  }
};

window.deleteCase = async function (caseId, title) {
  if (!confirm(`Permanently delete case "${title}" and all of its associated evidence and records? This cannot be undone.`)) return;
  try {
    const data = await api(`/api/cases/${caseId}`, { method: "DELETE" });
    CASE_STATE = data.state;
    renderAll(false);
    if (data.cleanup_warning) alert(data.message);
  } catch (err) {
    alert(err.message);
  }
};

window.deleteActiveCase = function () {
  const active = CASE_STATE?.active_case;
  if (!active) return;
  window.deleteCase(active.id, active.title || active.case_code);
};

window.handleFileUpload = async function (file) {
  if (!file) return;
  const st = $("upload-status");
  if (st) st.textContent = `Verifying investigator face before ingesting ${file.name}…`;
  try {
    await captureFaceForAction("evidence_upload");
    if (st) st.textContent = `Ingesting & hashing ${file.name}…`;
    const form = new FormData();
    form.append("file", file);
    const data = await api("/api/upload", { method: "POST", body: form }, false);
    CASE_STATE = data.state;
    if (st) st.textContent = `Ingested ${file.name} (Face verified & SHA-256 locked).`;
    renderAll(true);
  } catch (err) {
    if (st) st.textContent = err.message;
    alert(err.message);
  } finally {
    const input = $("file-input");
    if (input) input.value = "";
  }
};

window.deleteEvidence = async function (code, filename) {
  if (!confirm(`Retire artifact ${filename} (${code}) from active analysis? Live face verification is required.`)) return;
  try {
    await captureFaceForAction("evidence_retire");
    const data = await api(`/api/evidence/${encodeURIComponent(code)}`, { method: "DELETE" }, false);
    CASE_STATE = data.state;
    renderAll(true);
  } catch (err) {
    alert(err.message);
  }
};

window.saveEventNote = async function (eventId) {
  const val = $(`note-input-${eventId}`)?.value || "";
  try {
    const data = await api(`/api/events/${eventId}/note`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: val }),
    });
    CASE_STATE = data.state;
    renderTimeline();
  } catch (err) {
    alert(err.message);
  }
};

window.exportCaseJson = async function () {
  if (!CASE_STATE) return;
  try {
    await api("/api/authorize/export", { method: "POST" });
    const blob = new Blob([JSON.stringify(CASE_STATE, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${(CASE_STATE.active_case?.case_code || "CRIME404").replace("#", "")}_Forensic_Bundle.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    alert(err.message);
  }
};

window.printForensicDossier = async function () {
  try {
    await api("/api/authorize/export", { method: "POST" });
    window.print();
  } catch (err) {
    alert(err.message);
  }
};

// Profile, Biometrics & Passkey Handlers
async function loadUserProfile() {
  try {
    const p = await api("/api/profile");
    if ($("prof-username")) $("prof-username").textContent = p.username;
    if ($("profile-name")) $("profile-name").textContent = p.username || "Investigator";
    if ($("prof-email-org")) $("prof-email-org").textContent = `${p.email || "Email not set"} · Organisation #${p.org_id || 1}`;
    if ($("prof-role-pill")) $("prof-role-pill").textContent = p.role;
    if ($("prof-mfa-pill")) $("prof-mfa-pill").textContent = p.mfa_enabled ? "MFA enabled" : "MFA disabled";
    if ($("prof-sessions")) $("prof-sessions").textContent = p.sessions_count ?? 1;
    if ($("prof-perms")) $("prof-perms").textContent = (p.permissions || []).join(", ") || "—";
    if ($("prof-bio-list")) {
      const labels = (p.passkeys || []).map((k) => `${k.label} (${k.id}…)`).join(", ");
      $("prof-bio-list").textContent = `Registered passkeys (${p.webauthn_count || 0}): ${labels || "None yet"}`;
    }
    if ($("prof-face-status")) {
      $("prof-face-status").textContent = !p.face_supported
        ? "Face verification engine unavailable · install requirements-biometric.txt"
        : p.face_enrolled
        ? "✓ Face identity enrolled · AES-256-GCM encrypted template active"
        : "⚠ Face identity not enrolled yet — click '+ Enroll Face Identity' to enable upload verification";
    }
    window.CRIME404_FACE_SUPPORTED = Boolean(p.face_detection_supported);
    window.CRIME404_FACE_VERIFICATION_SUPPORTED = Boolean(p.face_supported);
    if ($("face-detect-start")) $("face-detect-start").disabled = !p.face_detection_supported;
    if ($("face-detect-stop")) $("face-detect-stop").disabled = true;
    if ($("sec-role-badge")) $("sec-role-badge").textContent = p.role || "—";
    if ($("sec-mfa-status")) $("sec-mfa-status").textContent = p.mfa_enabled ? "Enabled" : "Disabled";
  } catch (err) {
    console.error(err);
  }
}
window.loadProfile = loadUserProfile;

let faceDetectionStream = null;
let faceDetectionVideo = null;
let faceDetectionTimer = null;
let faceDetectionBusy = false;

window.startCrime404FaceDetection = async function () {
  const status = $("prof-face-msg");
  const preview = $("face-detection-preview");
  const startBtn = $("face-detect-start");
  const stopBtn = $("face-detect-stop");
  try {
    if (!window.CRIME404_FACE_SUPPORTED) {
      throw new Error("Face detector is unavailable. Check OpenCV dependency and restart the server.");
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("Camera access requires localhost or HTTPS and a supported browser.");
    }
    faceDetectionStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: 640, height: 480 }, audio: false });
    faceDetectionVideo = document.createElement("video");
    faceDetectionVideo.autoplay = true;
    faceDetectionVideo.muted = true;
    faceDetectionVideo.playsInline = true;
    faceDetectionVideo.className = "w-full max-w-sm rounded-lg border border-slate-700 bg-black";
    preview.replaceChildren(faceDetectionVideo);
    faceDetectionVideo.srcObject = faceDetectionStream;
    await new Promise((resolve) => (faceDetectionVideo.onloadedmetadata = resolve));
    await faceDetectionVideo.play();
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 480;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    if (status) status.textContent = "Camera active. Scanning for faces…";
    faceDetectionTimer = window.setInterval(async () => {
      if (!faceDetectionVideo || faceDetectionBusy || faceDetectionVideo.readyState < 2) return;
      faceDetectionBusy = true;
      try {
        ctx.drawImage(faceDetectionVideo, 0, 0, canvas.width, canvas.height);
        const frame = canvas.toDataURL("image/jpeg", 0.6);
        const result = await api("/api/face/detect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ image: frame }),
        });
        if (status) status.textContent = `${result.message} (${result.face_count} face${result.face_count === 1 ? "" : "s"} in frame).`;
      } catch (err) {
        if (status) status.textContent = `Detection error: ${err.message}`;
      } finally {
        faceDetectionBusy = false;
      }
    }, 1000);
  } catch (err) {
    if (status) status.textContent = err.message;
    window.stopCrime404FaceDetection();
  }
};

window.stopCrime404FaceDetection = function () {
  if (faceDetectionTimer) window.clearInterval(faceDetectionTimer);
  faceDetectionTimer = null;
  if (faceDetectionStream) faceDetectionStream.getTracks().forEach((track) => track.stop());
  faceDetectionStream = null;
  if (faceDetectionVideo) faceDetectionVideo.srcObject = null;
  faceDetectionVideo = null;
  const preview = $("face-detection-preview");
  if (preview) preview.replaceChildren();
  const startBtn = $("face-detect-start");
  const stopBtn = $("face-detect-stop");
  if (startBtn) startBtn.disabled = !window.CRIME404_FACE_SUPPORTED;
  if (stopBtn) stopBtn.disabled = true;
  const status = $("prof-face-msg");
  if (status) status.textContent = "Camera stopped.";
};

window.enrollFaceTemplate = async function () {
  const st = $("prof-face-msg");
  let stream, video;
  try {
    const p = await api("/api/profile");
    if (!p.face_supported) {
      throw new Error("Face verification engine is unavailable. Install requirements-biometric.txt and restart Flask.");
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("Camera access requires HTTPS or localhost and a supported browser.");
    }
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: 640, height: 480 }, audio: false });
    video = document.createElement("video");
    video.autoplay = true;
    video.muted = true;
    video.playsInline = true;
    video.style.cssText = "position:fixed;right:18px;bottom:18px;width:220px;z-index:99999;border:2px solid #829783;border-radius:12px;background:#000";
    document.body.appendChild(video);
    video.srcObject = stream;
    await new Promise((resolve) => (video.onloadedmetadata = resolve));
    await video.play();
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 480;
    const ctx = canvas.getContext("2d");
    const images = [];
    for (let i = 0; i < 3; i++) {
      if (st) st.textContent = `Capturing sample ${i + 1} of 3 — look directly at the camera…`;
      await new Promise((resolve) => setTimeout(resolve, 900));
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      images.push(canvas.toDataURL("image/jpeg", 0.82));
    }
    const current_password = p.face_enrolled ? "" : prompt("Confirm your current password to enroll your face template:");
    if (!p.face_enrolled && !current_password) throw new Error("Face enrollment cancelled.");
    const mfa_code = !p.face_enrolled && p.mfa_enabled ? prompt("Enter your current 6-digit authenticator code:") || "" : "";
    const res = await api("/api/face/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ images, current_password, mfa_code }),
    });
    if (st) st.textContent = res.message || "Face template encrypted and enrolled.";
    loadUserProfile();
  } catch (err) {
    if (st) st.textContent = err.message;
  } finally {
    if (stream) stream.getTracks().forEach((t) => t.stop());
    if (video) video.remove();
  }
};

window.removeFaceTemplate = async function () {
  const st = $("prof-face-msg");
  try {
    const res = await api("/api/face/remove", { method: "POST" });
    if (st) st.textContent = res.message || "Face template removed.";
    loadUserProfile();
  } catch (err) {
    if (st) st.textContent = err.message;
  }
};

window.checkCrime404Camera = async function () {
  const status = $("camera-check-status");
  const btn = $("camera-check-btn");
  if (!status || !btn) return;
  btn.disabled = true;
  status.textContent = "Checking camera permission…";
  let stream;
  try {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("Camera unavailable · open CRIME404 on http://localhost:5000 or HTTPS.");
    }
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: false });
    const track = stream.getVideoTracks()[0];
    status.textContent = `Camera ready · ${track?.label || "video input active"}`;
  } catch (err) {
    status.textContent = `Camera check failed · ${err.message}`;
  } finally {
    if (stream) stream.getTracks().forEach((track) => track.stop());
    btn.disabled = false;
  }
};

window.changeProfilePassword = async function () {
  const cur = $("prof-cur-pw")?.value || "";
  const nw = $("prof-new-pw")?.value || "";
  const msg = $("prof-pw-msg");
  try {
    const res = await api("/api/profile/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: cur, new_password: nw }),
    });
    if (msg) msg.textContent = res.message || "Password updated.";
    if ($("prof-cur-pw")) $("prof-cur-pw").value = "";
    if ($("prof-new-pw")) $("prof-new-pw").value = "";
    if (res.relogin_required) window.location.href = "/login";
  } catch (err) {
    if (msg) msg.textContent = err.message;
  }
};

window.deleteProfile = async function () {
  const password = $("prof-delete-pw")?.value || "";
  const confirmation = $("prof-delete-confirm")?.value || "";
  const msg = $("prof-delete-msg");

  if (!password) {
    if (msg) msg.textContent = "Enter your current password first.";
    return;
  }
  if (confirmation !== "DELETE") {
    if (msg) msg.textContent = "Type DELETE exactly in the confirmation field.";
    return;
  }
  if (!window.confirm("Deactivate this profile? You will be signed out. Forensic cases, evidence originals, custody records, and audit history will remain preserved.")) {
    return;
  }

  try {
    const result = await api("/api/profile/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: password, confirmation }),
    });
    if (msg) msg.textContent = result.message || "Profile deactivated.";
    window.location.href = result.redirect || "/login";
  } catch (err) {
    if (msg) msg.textContent = err.message;
  }
};

window.triggerEncryptedBackup = async function () {
  const resEl = $("sec-backup-result");
  try {
    const res = await api("/api/backup/run", { method: "POST" });
    const b = res.backup || {};
    if (resEl) resEl.textContent = `Encrypted backup created: ${b.backup_filename} (${b.file_count} files, SHA-256: ${(b.plaintext_sha256 || "").slice(0, 12)}…)`;
  } catch (err) {
    if (resEl) resEl.textContent = `Backup error: ${err.message}`;
  }
};

// Organisation Team Invite Links & Members
window.loadOrgInvites = async function () {
  const listEl = $("sec-invites-list");
  if (!listEl) return;
  try {
    const data = await api("/api/org/invites");
    const invites = data.invites || [];
    listEl.innerHTML = invites.length
      ? invites
          .map(
            (inv) => `
          <div class="flex items-center justify-between gap-2 border-b border-slate-800 py-1">
            <span class="truncate text-slate-300"><strong>${esc(inv.assigned_role)}</strong> · ${inv.uses_count}/${inv.max_uses} uses · exp ${esc(inv.expires_at)}</span>
            <div class="flex gap-1 shrink-0">
              <button onclick="navigator.clipboard?.writeText('${esc(inv.invite_url)}')" class="text-sky-300 hover:underline">Copy</button>
              <button onclick="revokeOrgInvite(${inv.id})" class="text-rose-400 hover:underline ml-1">Revoke</button>
            </div>
          </div>`
          )
          .join("")
      : '<span class="text-slate-500">No active invite links yet. Generate one above to invite teammates or another Lead Investigator.</span>';
  } catch (err) {
    listEl.innerHTML = `<span class="text-slate-500">${esc(err.message)}</span>`;
  }
};

window.createOrgInviteLink = async function () {
  const role = $("sec-invite-role")?.value || "investigator";
  try {
    const res = await api("/api/org/invites", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, expires_hours: 48, max_uses: 10 }),
    });
    const box = $("sec-invite-generated");
    const urlInput = $("sec-invite-url-box");
    if (box && urlInput && res.invite?.invite_url) {
      urlInput.value = res.invite.invite_url;
      box.classList.remove("hidden-view");
    }
    loadOrgInvites();
  } catch (err) {
    alert(err.message);
  }
};

window.copyOrgInviteLink = function () {
  const urlInput = $("sec-invite-url-box");
  if (!urlInput) return;
  urlInput.select();
  navigator.clipboard?.writeText(urlInput.value);
};

window.revokeOrgInvite = async function (inviteId) {
  try {
    await api(`/api/org/invites/${inviteId}`, { method: "DELETE" });
    loadOrgInvites();
  } catch (err) {
    alert(err.message);
  }
};

window.acceptOrgInviteLink = async function () {
  const token = $("sec-join-token")?.value.trim();
  if (!token) return;
  try {
    const res = await api("/api/org/invites/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    alert(`Joined team! Your role is now ${res.role}.`);
    if ($("sec-join-token")) $("sec-join-token").value = "";
    await fetchCaseState();
    loadUserProfile();
    loadOrgUsers();
  } catch (err) {
    alert(err.message);
  }
};

window.setupMfaFlow = async function () {
  const password = prompt("Confirm your current password to configure authenticator MFA:");
  if (!password) return;
  try {
    const res = await api("/api/mfa/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const code = prompt(`${res.message}\n\nAuthenticator Secret: ${res.secret}\n\nEnter the 6-digit code from your authenticator app:`);
    if (!code) return;
    const enabled = await api("/api/mfa/enable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    alert(`MFA enabled! Save these single-use recovery codes:\n\n${(enabled.recovery_codes || []).join("\n")}`);
    loadUserProfile();
  } catch (err) {
    alert(err.message);
  }
};

window.logoutAllDevices = async function () {
  if (!confirm("Sign out all active sessions on every device?")) return;
  try {
    await api("/api/logout-all", { method: "POST" });
    window.location.href = "/login";
  } catch (err) {
    alert(err.message);
  }
};

window.logoutCurrentSession = async function () {
  try {
    await api("/logout", { method: "POST" });
  } finally {
    window.location.href = "/login";
  }
};

window.verifyAuditChainUI = async function () {
  const resEl = $("sec-audit-result");
  try {
    const res = await api("/api/audit/verify");
    if (resEl) resEl.textContent = `${res.verified ? "✓ VERIFIED" : "✗ TAMPER ALERT"} · ${res.message}`;
  } catch (err) {
    if (resEl) resEl.textContent = `Audit verification failed: ${err.message}`;
  }
};

window.loadAuditLogs = async function () {
  const table = $("sec-audit-table");
  if (!table) return;
  try {
    const res = await api("/api/audit/logs");
    table.innerHTML =
      (res.logs || [])
        .map(
          (r) =>
            `<div class="flex justify-between gap-2 border-b border-slate-800 pb-1"><span>${esc(r.timestamp_utc)} · ${esc(
              r.username
            )} · ${esc(r.action)}</span><span class="text-emerald-300">${esc(r.outcome)}</span></div>`
        )
        .join("") || '<p class="text-slate-400">No audit records yet.</p>';
  } catch (err) {
    table.innerHTML = `<p class="text-rose-400">${esc(err.message)}</p>`;
  }
};

window.loadCaseMembers = async function () {
  const caseId = CASE_STATE?.active_case?.id;
  const listEl = $("sec-case-members");
  const selectEl = $("sec-member-user");
  if (!caseId || !listEl) return;
  try {
    const res = await api(`/api/cases/${caseId}/members`);
    if (selectEl) {
      selectEl.innerHTML =
        (res.users || []).map((u) => `<option value="${esc(u.username)}">${esc(u.username)} (${esc(u.role)})</option>`).join("") ||
        '<option value="">No other org users</option>';
    }
    const items = [];
    if (res.owner) items.push(`<div><strong>${esc(res.owner.username)}</strong> · Case Owner</div>`);
    (res.members || []).forEach((m) => items.push(`<div><strong>${esc(m.username)}</strong> · ${esc(m.role)}</div>`));
    listEl.innerHTML = items.join("") || '<p class="text-slate-400">No assigned members yet.</p>';
  } catch (err) {
    listEl.innerHTML = `<p class="text-rose-400">${esc(err.message)}</p>`;
  }
};

window.assignCaseMember = async function () {
  const caseId = CASE_STATE?.active_case?.id;
  const username = $("sec-member-user")?.value;
  const role = $("sec-member-role")?.value;
  if (!caseId || !username) return;
  try {
    await api(`/api/cases/${caseId}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, role }),
    });
    loadCaseMembers();
  } catch (err) {
    alert(err.message);
  }
};

window.loadOrgUsers = async function () {
  const box = $("sec-org-users");
  if (!box) return;
  try {
    const data = await api("/api/org/users");
    const users = data.users || [];
    if (!users.length) {
      box.innerHTML = '<p class="text-slate-400 text-[11px]">No other users found in this organisation yet.</p>';
      return;
    }
    const roles = ["lead_investigator", "investigator", "evidence_reviewer", "read_only_auditor"];
    box.innerHTML = users
      .map(
        (u) => `
      <div class="flex items-center justify-between gap-2 border-b border-slate-800 py-1">
        <span class="truncate">${esc(u.username)} <span class="text-slate-400">(${esc(u.email)})</span></span>
        ${
          data.can_edit_roles
            ? `<select onchange="changeUserRole(${u.id}, this.value)" class="field !py-0.5 !px-1.5 !text-[11px] max-w-[160px]">
            ${roles.map((r) => `<option value="${r}" ${u.role === r ? "selected" : ""}>${r}</option>`).join("")}
          </select>`
            : `<span class="font-mono text-slate-300">${esc(u.role)}</span>`
        }
      </div>`
      )
      .join("");
  } catch (err) {
    box.innerHTML = `<p class="text-slate-400 text-[11px]">${esc(err.message)}</p>`;
  }
};

window.changeUserRole = async function (targetId, newRole) {
  try {
    await api(`/api/admin/users/${targetId}/role`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole }),
    });
    loadOrgUsers();
  } catch (err) {
    alert(`Could not update role: ${err.message}`);
    loadOrgUsers();
  }
};

// Event Listeners & Initialization
document.addEventListener("DOMContentLoaded", () => {
  const dropZone = $("drop-zone");
  const fileInput = $("file-input");

  if (dropZone && fileInput) {
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("border-sky-400", "bg-slate-900/80");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("border-sky-400", "bg-slate-900/80"));
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("border-sky-400", "bg-slate-900/80");
      if (e.dataTransfer.files?.length) handleFileUpload(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", (e) => {
      if (e.target.files?.length) handleFileUpload(e.target.files[0]);
    });
  }

  document.addEventListener("click", (e) => {
    const deleteEvBtn = e.target.closest('[data-action="delete-evidence"]');
    if (deleteEvBtn) {
      deleteEvidence(deleteEvBtn.dataset.code, deleteEvBtn.dataset.name);
      return;
    }
    const deleteCaseBtn = e.target.closest('[data-action="delete-case"]');
    if (deleteCaseBtn) {
      deleteCase(deleteCaseBtn.dataset.caseId, deleteCaseBtn.dataset.title);
      return;
    }
    const wrapper = $("exportDropdownWrapper");
    const menu = $("exportMenu");
    if (wrapper && menu && !wrapper.contains(e.target)) {
      menu.classList.add("hidden-view");
    }
  });

  window.exportJsonReport = window.exportCaseJson;
  window.openPrintableDossier = window.printForensicDossier;

  fetchCaseState();
});

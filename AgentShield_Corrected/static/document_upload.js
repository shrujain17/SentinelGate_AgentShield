/*
 * AgentShield production-bundle compatibility bridge.
 * The source React simulator has a native upload panel. This small adapter keeps
 * the precompiled dashboard usable when its bundle predates that React component.
 * It renders inside the existing Agent Simulator page and uses the same APIs.
 */
(() => {
  'use strict';

  const baseFetch = window.fetch.bind(window);
  const $ = (selector, root = document) => root.querySelector(selector);
  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes)) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  function appendFinding(container, finding) {
    const row = document.createElement('div');
    row.className = 'document-finding-row';
    const badge = document.createElement('span');
    badge.className = `badge ${['CRITICAL', 'HIGH'].includes(finding.severity) ? 'deny' : 'approval'}`;
    badge.textContent = finding.severity || 'NOTICE';
    const body = document.createElement('div');
    const title = document.createElement('b');
    title.textContent = finding.category || 'SECURITY FINDING';
    const excerpt = document.createElement('p');
    excerpt.textContent = finding.excerpt || finding.description || '';
    body.append(title, excerpt);
    row.append(badge, body);
    container.append(row);
  }

  function createPanel() {
    const panel = document.createElement('section');
    panel.className = 'panel document-security-panel document-security-bridge';
    panel.style.marginBottom = '1.25rem';
    panel.innerHTML = `
      <div class="panel-header">
        <div><h3 class="panel-title">📄 Real Document Upload & Inspection</h3>
          <p class="panel-subtitle">Actual PDF, DOCX, TXT and CSV contents are extracted and inspected before agent access</p></div>
        <span class="badge cyan">CONTENT-BASED ZERO TRUST</span>
      </div>
      <div class="document-upload-toolbar">
        <div style="flex:1;min-width:240px">
          <label class="document-field-label" for="agentshield-bridge-file">Select document</label>
          <input id="agentshield-bridge-file" class="form-select document-file-picker" type="file" accept=".pdf,.docx,.txt,.csv,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/csv" />
          <p class="document-help-text">Maximum upload size: 12 MB. Macros and embedded scripts are never executed.</p>
        </div>
        <div class="document-upload-actions">
          <button id="agentshield-bridge-scan" class="btn btn-primary" disabled>🛡️ Upload & Scan</button>
          <button id="agentshield-bridge-remove" class="btn btn-sm" disabled>Remove / Replace</button>
        </div>
      </div>
      <div id="agentshield-bridge-file-meta"></div>
      <div style="margin-top:0.8rem">
        <label class="document-field-label" for="agentshield-bridge-prompt">Agent task (optional)</label>
        <textarea id="agentshield-bridge-prompt" class="form-textarea" rows="2" placeholder="Summarize the uploaded document and identify its key facts.">Summarize the uploaded document and identify its key facts.</textarea>
      </div>
      <div id="agentshield-bridge-error" aria-live="polite"></div>
      <div id="agentshield-bridge-result"></div>`;

    const filePicker = $('#agentshield-bridge-file', panel);
    const scanButton = $('#agentshield-bridge-scan', panel);
    const removeButton = $('#agentshield-bridge-remove', panel);
    const fileMeta = $('#agentshield-bridge-file-meta', panel);
    const errorBox = $('#agentshield-bridge-error', panel);
    const resultBox = $('#agentshield-bridge-result', panel);
    let currentFile = null;
    let currentScan = null;

    const showError = (message) => {
      errorBox.replaceChildren();
      if (!message) return;
      const node = document.createElement('div');
      node.className = 'document-error';
      node.textContent = message;
      errorBox.append(node);
    };

    const showFile = () => {
      fileMeta.replaceChildren();
      if (!currentFile) return;
      const row = document.createElement('div');
      row.className = 'document-file-meta';
      const details = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = currentFile.name;
      const meta = document.createElement('span');
      meta.textContent = `${(currentFile.name.split('.').pop() || '').toUpperCase()} · ${formatBytes(currentFile.size)}`;
      details.append(name, meta);
      const status = document.createElement('span');
      status.className = 'badge cyan';
      status.textContent = 'READY TO SCAN';
      row.append(details, status);
      fileMeta.append(row);
    };

    const renderScan = (scan) => {
      resultBox.replaceChildren();
      const wrap = document.createElement('div');
      wrap.className = 'document-scan-result';
      const header = document.createElement('div');
      header.className = 'document-result-header';
      const left = document.createElement('div');
      const label = document.createElement('div');
      label.className = 'document-field-label';
      label.textContent = 'SECURITY DECISION';
      const decision = document.createElement('div');
      decision.className = `document-decision ${scan.decision}`;
      decision.textContent = scan.decision;
      const filename = document.createElement('div');
      filename.className = 'document-help-text';
      filename.textContent = `${scan.filename} · ${scan.format} · ${formatBytes(scan.file_size)} · ${new Date(scan.timestamp).toLocaleString()}`;
      left.append(label, decision, filename);
      const risk = document.createElement('div');
      risk.className = 'document-risk-score';
      const score = document.createElement('strong');
      score.textContent = `${Math.round((scan.risk_score || 0) * 100)}%`;
      const scoreLabel = document.createElement('span');
      scoreLabel.textContent = 'Risk score';
      risk.append(score, scoreLabel);
      header.append(left, risk);
      wrap.append(header);

      const grid = document.createElement('div');
      grid.className = 'document-status-grid';
      const metrics = [
        ['Extraction', scan.extraction_status], ['Chunks scanned', scan.chunks_scanned],
        ['Gateway enforcement', scan.gateway_enforcement_status], ['Agent access', scan.agent_access_status],
        ['Audit event', `#${scan.audit_event_id || '—'}`], ['Extracted characters', Number(scan.characters_extracted || 0).toLocaleString()],
      ];
      metrics.forEach(([caption, value]) => {
        const cell = document.createElement('div');
        const small = document.createElement('span');
        small.textContent = caption;
        const strong = document.createElement('strong');
        strong.textContent = value ?? '—';
        cell.append(small, strong);
        grid.append(cell);
      });
      wrap.append(grid);

      if ((scan.threats_detected || []).length) {
        const findings = document.createElement('div');
        findings.className = 'document-findings';
        const heading = document.createElement('strong');
        heading.textContent = 'Detected threat categories';
        const chips = document.createElement('div');
        chips.className = 'document-threat-chips';
        scan.threats_detected.forEach((threat) => {
          const chip = document.createElement('span');
          chip.textContent = threat;
          chips.append(chip);
        });
        findings.append(heading, chips);
        wrap.append(findings);
      }
      if ((scan.findings || []).length) {
        const findings = document.createElement('div');
        findings.className = 'document-findings';
        const heading = document.createElement('strong');
        heading.textContent = 'Suspicious excerpts';
        findings.append(heading);
        scan.findings.slice(0, 6).forEach((finding) => appendFinding(findings, finding));
        wrap.append(findings);
      }
      const preview = document.createElement('details');
      preview.className = 'document-preview';
      const summary = document.createElement('summary');
      summary.textContent = 'View extracted document content (preview)';
      const pre = document.createElement('pre');
      pre.textContent = scan.preview_text || 'No text preview available.';
      preview.append(summary, pre);
      wrap.append(preview);

      if (scan.decision === 'REVIEW' && scan.review_status === 'PENDING') {
        const review = document.createElement('div');
        review.className = 'document-review-actions';
        const message = document.createElement('span');
        message.textContent = 'Quarantined. The agent cannot access this document until a human reviewer decides.';
        const actions = document.createElement('div');
        const approve = document.createElement('button');
        approve.className = 'btn btn-sm btn-primary';
        approve.textContent = 'Approve for untrusted use';
        approve.addEventListener('click', () => reviewDocument(true));
        const reject = document.createElement('button');
        reject.className = 'btn btn-sm';
        reject.textContent = 'Reject';
        reject.addEventListener('click', () => reviewDocument(false));
        actions.append(approve, reject);
        review.append(message, actions);
        wrap.append(review);
      } else if (scan.review_status === 'REJECTED') {
        const rejected = document.createElement('div');
        rejected.className = 'document-error';
        rejected.textContent = 'Reviewer rejected this document. Agent access is blocked.';
        wrap.append(rejected);
      }

      const controls = document.createElement('div');
      controls.className = 'document-agent-actions';
      const run = document.createElement('button');
      run.className = 'btn btn-primary';
      run.textContent = '▶ Process scanned document with Agent';
      const canRun = scan.decision === 'ALLOW' || (scan.decision === 'REVIEW' && scan.review_status === 'APPROVED');
      run.disabled = !canRun;
      run.addEventListener('click', processDocument);
      const note = document.createElement('span');
      note.textContent = scan.decision === 'BLOCK' ? 'Blocked documents are never forwarded to the agent.' : scan.decision === 'REVIEW' && scan.review_status !== 'APPROVED' ? 'Human approval is required before processing.' : 'The agent receives the document only as untrusted reference material.';
      controls.append(run, note);
      wrap.append(controls);
      resultBox.append(wrap);
    };

    async function reviewDocument(approved) {
      if (!currentScan) return;
      try {
        const response = await fetch(`/api/v1/documents/${encodeURIComponent(currentScan.scan_id)}/review`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ approved, reviewer_notes: 'Reviewed in AgentShield SOC dashboard.' }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Document review failed.');
        currentScan = data;
        removeButton.disabled = false;
        renderScan(data);
      } catch (error) { showError(error.message); }
    }

    async function processDocument() {
      if (!currentScan) return;
      const runButton = $('.document-agent-actions button', resultBox);
      if (runButton) { runButton.disabled = true; runButton.textContent = '⏳ Agent processing...'; }
      try {
        const prompt = ($('#agentshield-bridge-prompt', panel)?.value || '').trim() || 'Summarize the uploaded document and identify its key facts.';
        const response = await fetch('/api/v1/agent/run', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_prompt: prompt, document_scan_id: currentScan.scan_id, ai_provider: 'mock' }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Agent processing failed.');
        const output = document.createElement('div');
        output.className = 'document-agent-output';
        const heading = document.createElement('strong');
        heading.textContent = `AGENT RESULT · ${data.status || 'COMPLETED'}`;
        const pre = document.createElement('pre');
        pre.textContent = data.final_response || JSON.stringify(data, null, 2);
        output.append(heading, pre);
        resultBox.append(output);
        if (runButton) runButton.textContent = '✓ Agent processing complete';
      } catch (error) {
        showError(error.message);
        if (runButton) { runButton.disabled = false; runButton.textContent = '▶ Process scanned document with Agent'; }
      }
    }

    panel.__agentshieldBridge = {
      async scanText(text, prompt) {
        const form = new FormData();
        form.append('file', new Blob([text], { type: 'text/plain' }), 'simulated-context.txt');
        const response = await baseFetch('/api/v1/documents/scan', { method: 'POST', body: form });
        const data = await response.json();
        if (!response.ok) {
          const message = typeof data.detail === 'string' ? data.detail : data.detail?.message || 'Text-context scan failed.';
          throw new Error(message);
        }
        currentScan = data;
        removeButton.disabled = false;
        const promptField = $('#agentshield-bridge-prompt', panel);
        if (promptField && prompt) promptField.value = prompt;
        renderScan(data);
        showError('Legacy simulator context was routed through the real text upload scanner. It was not passed directly to the agent.');
        return data;
      },
    };

    filePicker.addEventListener('change', async () => {
      try {
        if (currentScan?.scan_id) {
          await baseFetch(`/api/v1/documents/${encodeURIComponent(currentScan.scan_id)}`, { method: 'DELETE' });
        }
        currentFile = filePicker.files?.[0] || null;
        currentScan = null;
        resultBox.replaceChildren();
        showError('');
        showFile();
        scanButton.disabled = !currentFile;
        removeButton.disabled = !currentFile;
      } catch (error) {
        showError(error.message || 'Unable to replace previous document scan.');
      }
    });
    removeButton.addEventListener('click', async () => {
      try {
        if (currentScan?.scan_id) {
          const response = await baseFetch(`/api/v1/documents/${encodeURIComponent(currentScan.scan_id)}`, { method: 'DELETE' });
          if (!response.ok && response.status !== 404) throw new Error('Unable to remove the stored document scan.');
        }
        currentFile = null;
        currentScan = null;
        filePicker.value = '';
        fileMeta.replaceChildren();
        resultBox.replaceChildren();
        showError('');
        scanButton.disabled = true;
        removeButton.disabled = true;
      } catch (error) { showError(error.message || 'Unable to remove document.'); }
    });
    scanButton.addEventListener('click', async () => {
      if (!currentFile) return;
      scanButton.disabled = true;
      scanButton.textContent = '⏳ Extracting & scanning...';
      resultBox.replaceChildren();
      showError('');
      try {
        if (currentScan?.scan_id) {
          const removed = await baseFetch(`/api/v1/documents/${encodeURIComponent(currentScan.scan_id)}`, { method: 'DELETE' });
          if (!removed.ok && removed.status !== 404) throw new Error('Unable to replace the previous document scan.');
          currentScan = null;
        }
        const form = new FormData();
        form.append('file', currentFile);
        const response = await fetch('/api/v1/documents/scan', { method: 'POST', body: form });
        const data = await response.json();
        if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || 'Document scan failed.');
        currentScan = data;
        removeButton.disabled = false;
        renderScan(data);
      } catch (error) { showError(error.message); }
      finally { scanButton.disabled = !currentFile; scanButton.textContent = '🛡️ Upload & Scan'; }
    });

    return panel;
  }

  function ensurePanel() {
    if ($('.document-security-panel')) return;
    const heading = [...document.querySelectorAll('.panel-title')].find((node) => node.textContent.includes('Tool Call & Agent Request Composer'));
    if (!heading) return;
    const composerPanel = heading.closest('.panel');
    const grid = composerPanel?.parentElement;
    const pageRoot = grid?.parentElement;
    if (!composerPanel || !grid || !pageRoot) return;
    const panel = createPanel();
    pageRoot.insertBefore(panel, grid);
  }

  // Older precompiled bundles sent their simulator's text context as a raw
  // document_content field. Intercept that legacy contract and route it through
  // the same upload scanner before the agent endpoint is called. The current
  // React source already uses document_scan_id directly.
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (url.includes('/api/v1/agent/run') && typeof init.body === 'string') {
      let payload;
      try { payload = JSON.parse(init.body); } catch (_) { payload = null; }
      if (payload && typeof payload.document_content === 'string' && payload.document_content.trim()) {
        const bridgePanel = $('.document-security-bridge');
        const bridge = bridgePanel && bridgePanel.__agentshieldBridge;
        if (!bridge || typeof bridge.scanText !== 'function') {
          return new Response(JSON.stringify({ detail: 'Untrusted text cannot be forwarded directly. Upload and scan it first.' }), {
            status: 400, headers: { 'Content-Type': 'application/json' },
          });
        }
        try {
          const scan = await bridge.scanText(payload.document_content, payload.user_prompt);
          if (scan.decision === 'BLOCK') {
            return new Response(JSON.stringify({ detail: 'AgentShield blocked the supplied text context. It was not sent to the agent.' }), {
              status: 403, headers: { 'Content-Type': 'application/json' },
            });
          }
          if (scan.decision === 'REVIEW') {
            return new Response(JSON.stringify({ detail: 'The supplied text context is quarantined for human review. Approve it in the Document Security panel before processing.' }), {
              status: 409, headers: { 'Content-Type': 'application/json' },
            });
          }
          delete payload.document_content;
          payload.document_scan_id = scan.scan_id;
          init = { ...init, body: JSON.stringify(payload) };
        } catch (error) {
          return new Response(JSON.stringify({ detail: error.message || 'Document scan failed.' }), {
            status: 422, headers: { 'Content-Type': 'application/json' },
          });
        }
      }
    }
    return baseFetch(input, init);
  };

  function start() {
    ensurePanel();
    const observer = new MutationObserver(() => ensurePanel());
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();

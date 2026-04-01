/* ZeroProbe — main.js */
'use strict';

/* ── Sidebar mobile toggle ─────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const sidebar = document.getElementById('sidebar');
  const toggle  = document.getElementById('sidebarToggle');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (sidebar.classList.contains('open') &&
          !sidebar.contains(e.target) && e.target !== toggle) {
        sidebar.classList.remove('open');
      }
    });
  }
});

/* ── AI output colorizer ─────────────────────────────────────────────────────── */
function colorizeAI(id) {
  const box = document.getElementById(id);
  if (!box) return;
  box.innerHTML = box.innerHTML
    .replace(/\[VULN:.*?\]/g,            m => `<span class="ai-vuln">${m}</span>`)
    .replace(/Overall Assessment:.*/g,   m => `<span class="ai-overall">${m}</span>`)
    .replace(/^(Fix:|Description:|Risk:|Secure Example:)/gm,
                                          m => `<span class="ai-label">${m}</span>`)
    .replace(/^(\d+\. .+)/gm,           m => `<span class="ai-step">${m}</span>`)
    .replace(/---/g, '<span class="ai-sep">─────────────────────────────────────</span>');
}

/* ── AI color classes (injected) ─────────────────────────────────────────────── */
(function injectAIStyles() {
  const s = document.createElement('style');
  s.textContent = `
    .ai-vuln    { color:#F87171; font-weight:700; display:block; margin-top:4px; }
    .ai-overall { color:#FCD34D; font-weight:700; display:block; margin-top:8px; }
    .ai-label   { color:#60A5FA; font-weight:600; }
    .ai-step    { color:#34D399; display:block; }
    .ai-sep     { color:#1E293B; display:block; margin:8px 0; }
  `;
  document.head.appendChild(s);
})();

/* ── Scanner with SSE ───────────────────────────────────────────────────────── */
const scanForm = document.getElementById('scanForm');
if (scanForm) {
  scanForm.addEventListener('submit', async e => {
    e.preventDefault();

    const btn       = document.getElementById('scanBtn');
    const panel     = document.getElementById('scanPanel');
    const pctEl     = document.getElementById('scanPct');
    const stageEl   = document.getElementById('scanStage');
    const barEl     = document.getElementById('scanBar');
    const logEl     = document.getElementById('scanLog');

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning…';
    panel.classList.add('active');

    // Stage chips
    const chips = {
      xss:     document.getElementById('stageXSS'),
      sqli:    document.getElementById('stageSQLi'),
      headers: document.getElementById('stageHeaders'),
      ai:      document.getElementById('stageAI'),
    };

    function setChip(name, state) {
      const el = chips[name];
      if (!el) return;
      el.classList.remove('active', 'done');
      if (state) el.classList.add(state);
    }

    function addLog(msg, highlight = false) {
      if (!logEl) return;
      const span = document.createElement('span');
      span.className = `log-line${highlight ? ' highlight' : ''}`;
      span.textContent = msg;
      logEl.appendChild(span);
      logEl.scrollTop = logEl.scrollHeight;
    }

    const fd  = new FormData(scanForm);
    const res = await fetch('/scan', { method: 'POST', body: fd });
    const json = await res.json();

    if (json.error) {
      stageEl.textContent = json.error;
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Scan';
      return;
    }

    const evtSrc = new EventSource(`/scan-progress/${json.scan_id}`);

    evtSrc.onmessage = evt => {
      const d = JSON.parse(evt.data);

      barEl.style.width   = d.progress + '%';
      pctEl.textContent   = d.progress + '%';
      stageEl.textContent = d.stage || '';

      // Update chips
      if (d.progress >= 14) setChip('xss',     d.progress >= 42 ? 'done' : 'active');
      if (d.progress >= 42) setChip('sqli',    d.progress >= 70 ? 'done' : 'active');
      if (d.progress >= 70) setChip('headers', d.progress >= 80 ? 'done' : 'active');
      if (d.progress >= 88) setChip('ai',      d.progress >= 100 ? 'done' : 'active');

      // New log lines
      if (d.logs && Array.isArray(d.logs)) {
        const currentCount = logEl ? logEl.children.length : 0;
        for (let i = currentCount; i < d.logs.length; i++) {
          addLog(d.logs[i], d.logs[i].includes('complete') || d.logs[i].includes('Scan'));
        }
      }

      if (d.status === 'done') {
        evtSrc.close();
        window.location.href = `/report/${d.record_id}`;
      } else if (d.status === 'error') {
        evtSrc.close();
        stageEl.textContent = d.stage;
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Retry';
        barEl.style.background = 'var(--red)';
      }
    };

    evtSrc.onerror = () => {
      evtSrc.close();
      stageEl.textContent = 'Connection lost. Please retry.';
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Retry';
    };
  });
}

/* ── Generic form loader ─────────────────────────────────────────────────────── */
document.querySelectorAll('[data-loading-form]').forEach(form => {
  form.addEventListener('submit', () => {
    const btn = form.querySelector('[data-loading-btn]');
    const lbl = form.querySelector('[data-loading-label]');
    const ind = form.querySelector('[data-loading-indicator]');
    if (btn) btn.disabled = true;
    if (lbl) lbl.textContent = btn?.dataset.loadingText || 'Working…';
    if (ind) ind.classList.add('active');
  });
});

/* ── Run on page load ────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  colorizeAI('aiBox');
  // Animate page elements
  document.querySelectorAll('.fade-up').forEach((el, i) => {
    el.style.animationDelay = `${i * 0.05}s`;
  });
});

// Keylogger Lab — frontend. All capture happens only inside this page's own
// demo inputs, and only while the simulated logger is running.
const $ = (id) => document.getElementById(id);

const KEY_LABELS = {
  Enter: '[Enter]', Backspace: '[Backspace]', Tab: '[Tab]', Escape: '[Esc]',
  Shift: '[Shift]', Control: '[Ctrl]', Alt: '[Alt]', Meta: '[Meta]',
  CapsLock: '[Caps]', ArrowUp: '[Up]', ArrowDown: '[Down]',
  ArrowLeft: '[Left]', ArrowRight: '[Right]', Delete: '[Del]', ' ': '[Space]',
};

let lastStatus = null;
let scanHistoryLoaded = false;

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...(opts || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function fmtTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
}
function fmtClock(ms) {
  if (ms == null || ms < 0) ms = 0;
  const s = Math.floor(ms / 1000);
  const h = String(Math.floor(s / 3600)).padStart(1, '0');
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  return `${h}:${m}:${ss}`;
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- tabs ----------
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tabpanel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'chain') renderSystemTables();
    if (btn.dataset.tab === 'console') loadScanHistory();
  });
});

// ---------- keystroke capture (demo inputs only) ----------
document.querySelectorAll('.demo-input').forEach((el) => {
  el.addEventListener('keydown', (e) => {
    if (!lastStatus || !lastStatus.sim.running) return;
    const key = KEY_LABELS[e.key] || (e.key.length === 1 ? e.key : `[${e.key}]`);
    api('/api/sim/keystroke', {
      method: 'POST',
      body: JSON.stringify({ key, field: el.dataset.field || 'demo' }),
    }).catch(() => {});
  });
  el.addEventListener('copy', (e) => {
    if (!lastStatus || !lastStatus.sim.running) return;
    const text = el.value.slice(el.selectionStart, el.selectionEnd) || el.value;
    api('/api/sim/clipboard', { method: 'POST', body: JSON.stringify({ text }) }).catch(() => {});
  });
});

// Stop hotkey: Esc halts the logger immediately (safety guard from the report).
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && lastStatus && lastStatus.sim.running) stopSim();
});

$('fakeLoginBtn').addEventListener('click', () => {
  $('loginMsg').textContent = 'Sign-in failed (as expected — this form goes nowhere). But if the logger was running, everything you typed is already in its buffer.';
});

// ---------- controls ----------
$('startSimBtn').addEventListener('click', async () => {
  $('simError').textContent = '';
  try {
    await api('/api/sim/start', {
      method: 'POST',
      body: JSON.stringify({
        flushSeconds: Number($('flushSeconds').value),
        persist: $('optPersist').checked,
        clipboard: $('optClipboard').checked,
        screenshots: $('optShots').checked,
      }),
    });
    refresh();
  } catch (e) { $('simError').textContent = e.message; }
});

async function stopSim() {
  $('simError').textContent = '';
  try { await api('/api/sim/stop', { method: 'POST' }); refresh(); }
  catch (e) { $('simError').textContent = e.message; }
}
$('stopSimBtn').addEventListener('click', stopSim);

$('flushNowBtn').addEventListener('click', async () => {
  try { await api('/api/sim/flush', { method: 'POST' }); refresh(); }
  catch (e) { $('simError').textContent = e.message; }
});

$('baselineBtn').addEventListener('click', async () => {
  const r = await api('/api/detect/baseline', { method: 'POST' });
  $('baselineNote').textContent = 'Baseline taken at ' + fmtTime(r.baseline.takenAt) + ' — detector now reports only what is new since then.';
  refresh();
});

$('scanBtn').addEventListener('click', async () => {
  const r = await api('/api/detect/scan', { method: 'POST' });
  renderFindings(r.scan);
  loadScanHistory();
  refresh();
});

$('resetLabBtn').addEventListener('click', async () => {
  await api('/api/lab/reset', { method: 'POST' });
  $('findingsList').innerHTML = '<p class="muted">No scan run yet. Start the keylogger, type something, then scan.</p>';
  $('verdictPill').textContent = 'not scanned yet';
  $('verdictPill').className = 'pill';
  $('suiteSummary').textContent = 'Not run yet in this session.';
  $('testResults').innerHTML = '<p class="muted">Press “Run all 12 cases”.</p>';
  loadScanHistory();
  refresh();
});

$('runTestsBtn').addEventListener('click', async () => {
  $('suiteSummary').textContent = 'Running…';
  const r = await api('/api/tests/run', { method: 'POST' });
  const s = r.suite;
  $('suiteSummary').textContent = `${s.passed}/${s.total} passed · ${s.failed} failed · ${s.durationMs} ms`;
  $('testResults').innerHTML = s.results.map((t) => `
    <div class="test-case ${t.pass ? 'pass' : 'fail'}">
      <span class="test-badge ${t.pass ? 'pass' : 'fail'}">${t.pass ? 'PASS' : 'FAIL'}</span>
      <div><strong>Case ${t.id} — ${esc(t.name)}</strong>
      <p class="detail">${esc(t.detail)}</p></div>
    </div>`).join('');
});

// ---------- rendering ----------
function renderFindings(scan) {
  const pill = $('verdictPill');
  pill.textContent = 'verdict = ' + scan.verdict;
  pill.className = 'pill ' + (scan.verdict === 'CLEAN' ? 'clean' : 'suspicious');
  if (!scan.findings.length) {
    $('findingsList').innerHTML = `<p><span class="verdict-clean">CLEAN.</span> No rule fired — nothing new vs the baseline. Scanned in ${scan.durationMs} ms.</p>`;
    return;
  }
  $('findingsList').innerHTML = scan.findings.map((f) => `
    <div class="finding ${f.severity.toLowerCase()}">
      <div class="finding-head">
        <span class="sev ${f.severity}">${f.severity}</span>
        <span class="rule">${esc(f.rule)} · ${esc(f.mitre)}</span>
      </div>
      <p>${esc(f.title)}</p>
      <div class="evidence">${esc(f.evidence)}</div>
    </div>`).join('') +
    `<p class="muted small">Scan #${scan.id} · ${fmtTime(scan.scannedAt)} · ${scan.durationMs} ms · baseline ${fmtTime(scan.baselineUsed)}</p>`;
}

async function loadScanHistory() {
  try {
    const r = await api('/api/detect/scans');
    const rows = r.scans.map((s) => `
      <tr>
        <td>${s.id}</td><td>${fmtTime(s.scanned_at)}</td>
        <td class="${s.verdict === 'CLEAN' ? 'verdict-clean' : 'verdict-suspicious'}">${s.verdict}</td>
        <td>${s.findings_count} (${s.high_count} high, ${s.med_count} med)</td>
        <td>${s.duration_ms}</td>
      </tr>`).join('');
    $('scanHistory').querySelector('tbody').innerHTML =
      rows || '<tr><td colspan="5" class="muted">No scans recorded yet.</td></tr>';
  } catch { /* history is best-effort */ }
}

function renderSystemTables() {
  if (!lastStatus) return;
  const sys = lastStatus.system;
  $('procTable').querySelector('tbody').innerHTML = sys.processes.map((p) => `
    <tr class="${p.pid === 4172 ? 'flagged' : ''}">
      <td>${p.pid}</td><td>${esc(p.name)}</td><td>${esc(p.user)}</td>
      <td>${p.hasWindow ? 'yes' : 'no'}</td><td>${esc(p.modules.join(', '))}</td>
    </tr>`).join('');
  $('startupTable').querySelector('tbody').innerHTML = sys.startup.map((s) => `
    <tr class="${s.name === 'WinUpdateSvc' ? 'flagged' : ''}">
      <td>${esc(s.location)}</td><td>${esc(s.name)}</td>
    </tr>`).join('');
  $('connTable').querySelector('tbody').innerHTML = sys.connections.map((c) => `
    <tr class="${c.pid === 4172 ? 'flagged' : ''}">
      <td>${esc(c.process)} (${c.pid})</td><td>${esc(c.local)} → ${esc(c.remote)}</td><td>${esc(c.state)}</td>
    </tr>`).join('');
}

function renderChainLive(st) {
  const set = (key, text, hot) => {
    const el = document.querySelector(`[data-live="${key}"]`);
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('hot', !!hot);
    el.closest('.chain-step').classList.toggle('hot', !!hot);
  };
  set('hook', st.sim.running ? 'HOOK ACTIVE — update-svc.exe (pid 4172) holds kbdhook.dll' : 'idle', st.sim.running);
  set('buffer', st.sim.running ? `${st.sim.buffered} keys in memory buffer` : 'idle', st.sim.running && st.sim.buffered > 0);
  set('flush', st.sim.flushes > 0 ? `${st.sim.flushes} flush cycles · last ${fmtTime(st.sim.lastFlushAt)}` : (st.sim.running ? `next flush in ${fmtClock(st.sim.nextFlushAt ? new Date(st.sim.nextFlushAt) - Date.now() : 0)}` : 'idle'), st.sim.running);
  set('send', st.sim.outboxCount > 0 ? `${st.sim.outboxCount} transmissions via SMTP_SSL :465` : 'idle', st.sim.outboxCount > 0);
  set('persist', st.system.startup.some((s) => s.name === 'WinUpdateSvc') ? 'Run key present — WinUpdateSvc' : 'no Run key', st.system.startup.some((s) => s.name === 'WinUpdateSvc'));
}

async function refresh() {
  try {
    const st = await api('/api/status');
    lastStatus = st;
    const running = st.sim.running;

    // header + pills
    $('labStatus').textContent = running ? 'LAB-VM-01 · LOGGER RUNNING' : 'LAB-VM-01 · idle';
    $('sessionClock').textContent = 'session ' + fmtClock(st.session.remainingMs);
    $('simPill').textContent = running ? 'logger running' : 'logger stopped';
    $('simPill').className = 'pill ' + (running ? 'on' : 'off');
    $('startSimBtn').disabled = running;
    $('stopSimBtn').disabled = !running;
    $('flushNowBtn').disabled = !running && st.sim.buffered === 0;
    ['capTagLogin', 'capTagNotes', 'capTagBank'].forEach((id) => {
      const el = $(id);
      el.textContent = running ? 'CAPTURING' : 'not capturing';
      el.classList.toggle('live', running);
    });

    // stats + buffer
    $('statKeys').textContent = st.sim.keysCaptured;
    $('statBuffered').textContent = st.sim.buffered;
    $('statFlushes').textContent = st.sim.flushes;
    $('statLost').textContent = st.sim.keysLost;
    $('statNextFlush').textContent = running && st.sim.nextFlushAt
      ? fmtClock(new Date(st.sim.nextFlushAt) - Date.now()) : '—';
    $('bufferBox').textContent = st.sim.bufferPreview
      ? st.sim.bufferPreview + (st.sim.buffered > 40 ? `\n… (${st.sim.buffered - 40} more keys in buffer)` : '')
      : 'Buffer empty. Start the keylogger and type in the demo windows above.';

    // baseline note
    if (st.baselineTakenAt) {
      $('baselineNote').textContent = 'Baseline taken at ' + fmtTime(st.baselineTakenAt) + ' — detector now reports only what is new since then.';
    }

    renderChainLive(st);
    renderSystemTables();
  } catch { /* polling is best-effort; UI keeps last state */ }
}

async function refreshFeeds() {
  try {
    const d = await api('/api/sim/outbox');
    $('outboxList').innerHTML = d.outbox.length ? d.outbox.slice(-5).reverse().map((o) => `
      <div class="feed-item bad">
        <span class="tag-high">SENT (simulated)</span> · ${fmtTime(o.at)} · ${o.keys} keys · ${o.bytes} bytes<br>
        <span class="mono">${esc(o.channel)} · ${esc(o.reason)} flush · preview: “${esc(o.preview)}”</span>
      </div>`).join('') : '<p class="muted">No transmissions yet.</p>';
    $('clipboardList').innerHTML = d.clipboardLog.length ? d.clipboardLog.slice(-4).reverse().map((c) => `
      <div class="feed-item"><span class="mono">${fmtTime(c.at)}</span> · “${esc(c.text)}”</div>`).join('')
      : '<p class="muted">Clipboard capture off — nothing logged.</p>';
    $('shotsList').innerHTML = d.shots.length ? d.shots.slice(-4).reverse().map((s) => `
      <div class="feed-item"><span class="mono">${fmtTime(s.at)}</span> · screenshot of ${esc(s.window)} (simulated)</div>`).join('')
      : '<p class="muted">Screenshot capture off — nothing captured.</p>';
  } catch { /* best-effort */ }
}

refresh();
loadScanHistory();
setInterval(refresh, 1500);
setInterval(refreshFeeds, 2000);

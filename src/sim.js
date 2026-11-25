// Simulated lab system + keylogger engine.
//
// This is a SIMULATION. Nothing here touches a real keyboard, a real process
// table or a real mailbox. The "victim machine" is a small in-memory model of
// a Windows 11 workstation (processes, startup entries, network connections).
// The simulated keylogger only ever sees keystrokes typed inside this demo's
// own input fields, and its "exfiltrated" mail only ever lands in an on-screen
// outbox. Safety guards from the report are enforced in code:
//   - lab-only: the simulation runs only inside this demo
//   - no plain text on disk: the keystroke buffer lives in memory only
//   - stop hotkey: Esc (or the STOP button) halts the logger immediately
//   - 2-hour hard stop: the lab session ends 2h after the server starts
const db = require('./db');

const SESSION_LIMIT_MS = 2 * 60 * 60 * 1000; // 2-hour hard stop (report §safety)
const serverStartedAt = Date.now();

const CLEAN_PROCESSES = [
  { pid: 1120, name: 'explorer.exe', user: 'lab-user', cpu: 0.4, hasWindow: true, modules: ['shell32.dll'] },
  { pid: 2314, name: 'chrome.exe', user: 'lab-user', cpu: 3.1, hasWindow: true, modules: ['chrome.dll'] },
  { pid: 884, name: 'svchost.exe', user: 'SYSTEM', cpu: 0.2, hasWindow: false, modules: ['rpcrt4.dll'] },
  { pid: 902, name: 'svchost.exe', user: 'SYSTEM', cpu: 0.1, hasWindow: false, modules: ['dhcpcsvc.dll'] },
  { pid: 1480, name: 'SearchIndexer.exe', user: 'SYSTEM', cpu: 0.6, hasWindow: false, modules: ['mssrch.dll'] },
  { pid: 1760, name: 'OneDrive.exe', user: 'lab-user', cpu: 0.3, hasWindow: true, modules: ['onedrive.dll'] },
  { pid: 1950, name: 'SecurityHealthService.exe', user: 'SYSTEM', cpu: 0.2, hasWindow: false, modules: ['mpclient.dll'] },
  { pid: 2044, name: 'spoolsv.exe', user: 'SYSTEM', cpu: 0.1, hasWindow: false, modules: ['spoolss.dll'] },
];

const CLEAN_STARTUP = [
  { location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'OneDrive', value: '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background' },
  { location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'SecurityHealth', value: '%windir%\\system32\\SecurityHealthSystray.exe' },
];

const CLEAN_CONNECTIONS = [
  { pid: 2314, process: 'chrome.exe', local: '192.168.1.20:51244', remote: '142.250.80.46:443', proto: 'TCP', state: 'ESTABLISHED' },
  { pid: 1760, process: 'OneDrive.exe', local: '192.168.1.20:51210', remote: '52.96.12.34:443', proto: 'TCP', state: 'ESTABLISHED' },
  { pid: 884, process: 'svchost.exe', local: '192.168.1.20:53555', remote: '192.168.1.1:53', proto: 'UDP', state: '-' },
];

// The logger's own artefacts, exactly as the report describes them.
const LOGGER_PROCESS = {
  pid: 4172, // pid from the report's slide 1
  name: 'update-svc.exe',
  user: 'SYSTEM',
  cpu: 0.7,
  hasWindow: false,
  modules: ['kbdhook.dll', 'ws2_32.dll'],
};
const LOGGER_RUN_KEY = {
  location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  name: 'WinUpdateSvc',
  value: '"C:\\Users\\lab-user\\AppData\\Roaming\\update-svc.exe" /silent',
};
const LOGGER_CONNECTION = {
  pid: 4172,
  process: 'update-svc.exe',
  local: '192.168.1.20:51990',
  remote: 'smtp.mail-relay.example:465',
  proto: 'TCP',
  state: 'ESTABLISHED',
};

function freshSystem() {
  return {
    processes: CLEAN_PROCESSES.map((p) => ({ ...p, modules: [...p.modules] })),
    startup: CLEAN_STARTUP.map((s) => ({ ...s })),
    connections: CLEAN_CONNECTIONS.map((c) => ({ ...c })),
  };
}

const state = {
  sessionStartedAt: serverStartedAt,
  sim: {
    running: false,
    startedAt: null,
    flushSeconds: 30,
    persist: false,
    clipboard: false,
    screenshots: false,
    buffer: [], // in-memory only, never written to disk
    keysCaptured: 0,
    keysLost: 0,
    flushes: 0,
    outbox: [], // simulated SMTP transmissions (never a real email)
    clipboardLog: [],
    shots: [],
    lastFlushAt: null,
    nextFlushAt: null,
  },
  system: freshSystem(),
  baseline: null, // clean snapshot, taken automatically at boot
  lastScan: null,
};

let flushTimer = null;

function takeBaseline() {
  state.baseline = JSON.parse(JSON.stringify(state.system));
  state.baseline.takenAt = new Date().toISOString();
  return state.baseline;
}

// Clean snapshot at boot, exactly like the report's baseline-diff step.
takeBaseline();

function sessionRemainingMs() {
  return Math.max(0, SESSION_LIMIT_MS - (Date.now() - serverStartedAt));
}

function applyLoggerPresence() {
  const procs = state.system.processes;
  if (!procs.some((p) => p.pid === LOGGER_PROCESS.pid)) {
    procs.push({ ...LOGGER_PROCESS, modules: [...LOGGER_PROCESS.modules] });
  }
  const conns = state.system.connections;
  if (!conns.some((c) => c.pid === LOGGER_PROCESS.pid)) {
    conns.push({ ...LOGGER_CONNECTION });
  }
}

function removeLoggerPresence() {
  state.system.processes = state.system.processes.filter((p) => p.pid !== LOGGER_PROCESS.pid);
  state.system.connections = state.system.connections.filter((c) => c.pid !== LOGGER_PROCESS.pid);
}

function applyPersistence() {
  if (!state.system.startup.some((s) => s.name === LOGGER_RUN_KEY.name)) {
    state.system.startup.push({ ...LOGGER_RUN_KEY });
  }
}

function startSim({ flushSeconds = 30, persist = false, clipboard = false, screenshots = false }) {
  if (sessionRemainingMs() <= 0) return { ok: false, error: 'Lab session hit the 2-hour hard stop. Restart the server for a new session.' };
  if (state.sim.running) return { ok: false, error: 'Keylogger is already running.' };
  state.sim.running = true;
  state.sim.startedAt = Date.now();
  state.sim.flushSeconds = Math.min(300, Math.max(15, Number(flushSeconds) || 30));
  state.sim.persist = !!persist;
  state.sim.clipboard = !!clipboard;
  state.sim.screenshots = !!screenshots;
  state.sim.buffer = [];
  state.sim.nextFlushAt = Date.now() + state.sim.flushSeconds * 1000;
  applyLoggerPresence();
  if (state.sim.persist) applyPersistence();
  flushTimer = setInterval(() => flush('timer'), state.sim.flushSeconds * 1000);
  return { ok: true };
}

function stopSim() {
  if (!state.sim.running) return { ok: false, error: 'Keylogger is not running.' };
  clearInterval(flushTimer);
  flushTimer = null;
  state.sim.running = false;
  state.sim.startedAt = null;
  state.sim.nextFlushAt = null;
  // Flush whatever is left before dying, then drop the process + connection.
  if (state.sim.buffer.length > 0) flush('stop');
  removeLoggerPresence();
  // The Run key stays behind when persistence was on — that is the point:
  // the detector must still catch it after the process is gone.
  return { ok: true };
}

function ingestKeystroke({ key, field }) {
  if (!state.sim.running) return { ok: false, error: 'Keylogger is not running — keystroke was not captured.' };
  if (typeof key !== 'string' || key.length === 0) return { ok: false, error: 'Empty key.' };
  state.sim.buffer.push({ key, field: field || 'demo', at: new Date().toISOString() });
  state.sim.keysCaptured += 1;
  return { ok: true, buffered: state.sim.buffer.length };
}

function ingestClipboard({ text }) {
  if (!state.sim.running || !state.sim.clipboard) return { ok: false };
  const snippet = String(text || '').slice(0, 200);
  if (!snippet) return { ok: false };
  state.sim.clipboardLog.push({ text: snippet, at: new Date().toISOString() });
  return { ok: true };
}

function captureShot({ window }) {
  if (!state.sim.running || !state.sim.screenshots) return { ok: false };
  state.sim.shots.push({ window: window || 'demo desktop', at: new Date().toISOString() });
  return { ok: true };
}

function flush(reason) {
  const keys = state.sim.buffer.splice(0, state.sim.buffer.length);
  const text = keys.map((k) => k.key).join('');
  const bytes = Buffer.byteLength(text, 'utf8');
  const entry = {
    id: state.sim.outbox.length + 1,
    at: new Date().toISOString(),
    reason,
    keys: keys.length,
    bytes,
    channel: 'SMTP_SSL :465',
    preview: text.slice(0, 120),
    status: 'sent (simulated)',
  };
  state.sim.outbox.push(entry);
  state.sim.flushes += 1;
  state.sim.lastFlushAt = entry.at;
  state.sim.nextFlushAt = state.sim.running ? Date.now() + state.sim.flushSeconds * 1000 : null;
  db.recordFlush({ keys: keys.length, bytes, channel: 'SMTP_SSL :465' });
  if (state.sim.screenshots && state.sim.running) {
    captureShot({ window: 'demo desktop — login form' });
  }
  return entry;
}

function resetLab() {
  if (flushTimer) { clearInterval(flushTimer); flushTimer = null; }
  state.sim = {
    running: false, startedAt: null, flushSeconds: 30, persist: false,
    clipboard: false, screenshots: false, buffer: [], keysCaptured: 0,
    keysLost: 0, flushes: 0, outbox: [], clipboardLog: [], shots: [],
    lastFlushAt: null, nextFlushAt: null,
  };
  state.system = freshSystem();
  state.baseline = takeBaseline();
  state.lastScan = null;
  return { ok: true };
}

function publicStatus() {
  const flushStats = db.flushStats();
  return {
    session: {
      startedAt: new Date(state.sessionStartedAt).toISOString(),
      remainingMs: sessionRemainingMs(),
      hardStopHours: 2,
    },
    sim: {
      running: state.sim.running,
      startedAt: state.sim.startedAt ? new Date(state.sim.startedAt).toISOString() : null,
      flushSeconds: state.sim.flushSeconds,
      persist: state.sim.persist,
      clipboard: state.sim.clipboard,
      screenshots: state.sim.screenshots,
      buffered: state.sim.buffer.length,
      bufferPreview: state.sim.buffer.slice(-40).map((k) => k.key).join(''),
      keysCaptured: state.sim.keysCaptured,
      keysLost: state.sim.keysLost,
      flushes: state.sim.flushes,
      lastFlushAt: state.sim.lastFlushAt,
      nextFlushAt: state.sim.nextFlushAt ? new Date(state.sim.nextFlushAt).toISOString() : null,
      outboxCount: state.sim.outbox.length,
      clipboardCount: state.sim.clipboardLog.length,
      shotsCount: state.sim.shots.length,
    },
    system: state.system,
    baselineTakenAt: state.baseline ? state.baseline.takenAt : null,
    lastScan: state.lastScan,
    flushStats,
  };
}

module.exports = {
  state, takeBaseline, startSim, stopSim, ingestKeystroke, ingestClipboard,
  captureShot, flush, resetLab, publicStatus, sessionRemainingMs,
  LOGGER_PROCESS, LOGGER_RUN_KEY, LOGGER_CONNECTION,
};

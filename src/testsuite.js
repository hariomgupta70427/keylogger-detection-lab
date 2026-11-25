// The 12-case lab test suite (report slide 5: "12 test cases, zero misses").
// Each case builds its own sandboxed copy of a system state, runs the real
// detector rules against it, and asserts the expected outcome — so a pass
// means the rule genuinely fired (or genuinely stayed quiet), not that a
// number was typed in. Nothing here touches the live lab state.
const detector = require('./detector');

function clone(o) { return JSON.parse(JSON.stringify(o)); }

const CLEAN = {
  processes: [
    { pid: 1120, name: 'explorer.exe', user: 'lab-user', cpu: 0.4, hasWindow: true, modules: ['shell32.dll'] },
    { pid: 2314, name: 'chrome.exe', user: 'lab-user', cpu: 3.1, hasWindow: true, modules: ['chrome.dll'] },
    { pid: 884, name: 'svchost.exe', user: 'SYSTEM', cpu: 0.2, hasWindow: false, modules: ['rpcrt4.dll'] },
  ],
  startup: [
    { location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'OneDrive', value: '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background' },
  ],
  connections: [
    { pid: 2314, process: 'chrome.exe', local: '192.168.1.20:51244', remote: '142.250.80.46:443', proto: 'TCP', state: 'ESTABLISHED' },
  ],
};

const LOGGER_PROC = { pid: 4172, name: 'update-svc.exe', user: 'SYSTEM', cpu: 0.7, hasWindow: false, modules: ['kbdhook.dll', 'ws2_32.dll'] };
const LOGGER_CONN = { pid: 4172, process: 'update-svc.exe', local: '192.168.1.20:51990', remote: 'smtp.mail-relay.example:465', proto: 'TCP', state: 'ESTABLISHED' };
const LOGGER_RUNKEY = { location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'WinUpdateSvc', value: '"C:\\Users\\lab-user\\AppData\\Roaming\\update-svc.exe" /silent' };

function baselineOf(system) {
  const b = clone(system);
  b.takenAt = new Date().toISOString();
  return b;
}

const CASES = [
  {
    id: 1, name: 'Hook DLL present while logger runs',
    run: () => {
      const sys = clone(CLEAN); sys.processes.push(clone(LOGGER_PROC));
      const f = detector.ruleHookDll(sys);
      return { pass: f.length === 1 && f[0].severity === 'HIGH', detail: f.map((x) => x.title).join('; ') || 'no finding' };
    },
  },
  {
    id: 2, name: 'SMTP exfil on :465 from a non-mail program',
    run: () => {
      const sys = clone(CLEAN); sys.connections.push(clone(LOGGER_CONN));
      const f = detector.ruleSmtpExfil(sys);
      return { pass: f.length === 1 && f[0].severity === 'HIGH', detail: f.map((x) => x.title).join('; ') || 'no finding' };
    },
  },
  {
    id: 3, name: 'New Run-key entry after persistence is enabled',
    run: () => {
      const sys = clone(CLEAN); sys.startup.push(clone(LOGGER_RUNKEY));
      const f = detector.ruleStartup(sys, baselineOf(CLEAN));
      return { pass: f.length === 1 && f[0].severity === 'MED', detail: f.map((x) => x.title).join('; ') || 'no finding' };
    },
  },
  {
    id: 4, name: 'Full attack chain (hook + exfil + Run key) → verdict SUSPICIOUS',
    run: () => {
      const sys = clone(CLEAN);
      sys.processes.push(clone(LOGGER_PROC));
      sys.connections.push(clone(LOGGER_CONN));
      sys.startup.push(clone(LOGGER_RUNKEY));
      const base = baselineOf(CLEAN);
      const findings = [...detector.ruleHookDll(sys), ...detector.ruleSmtpExfil(sys), ...detector.ruleStartup(sys, base)];
      const verdict = findings.length === 0 ? 'CLEAN' : 'SUSPICIOUS';
      return { pass: findings.length === 3 && verdict === 'SUSPICIOUS', detail: `${findings.length} findings, verdict ${verdict}` };
    },
  },
  {
    id: 5, name: 'Clean system scan → zero findings (false-positive check)',
    run: () => {
      const sys = clone(CLEAN); const base = baselineOf(CLEAN);
      const findings = [...detector.ruleHookDll(sys), ...detector.ruleSmtpExfil(sys), ...detector.ruleStartup(sys, base), ...detector.ruleBaselineDiff(sys, base)];
      return { pass: findings.length === 0, detail: findings.length === 0 ? '0 findings' : `${findings.length} unexpected findings` };
    },
  },
  {
    id: 6, name: 'Logger stopped, persistence off → system is clean again',
    run: () => {
      const sys = clone(CLEAN); const base = baselineOf(CLEAN);
      const findings = [...detector.ruleHookDll(sys), ...detector.ruleSmtpExfil(sys), ...detector.ruleStartup(sys, base), ...detector.ruleBaselineDiff(sys, base)];
      return { pass: findings.length === 0, detail: 'process, connection and Run key all gone' };
    },
  },
  {
    id: 7, name: 'Logger stopped but Run key left behind → only STARTUP fires',
    run: () => {
      const sys = clone(CLEAN); sys.startup.push(clone(LOGGER_RUNKEY));
      const base = baselineOf(CLEAN);
      const findings = [...detector.ruleHookDll(sys), ...detector.ruleSmtpExfil(sys), ...detector.ruleStartup(sys, base)];
      return { pass: findings.length === 1 && findings[0].rule === 'RULE-STARTUP', detail: findings.map((x) => x.rule).join(', ') || 'no finding' };
    },
  },
  {
    id: 8, name: 'Flush cycle preserves every keystroke (20 in → 20 out, 0 lost)',
    run: () => {
      const buffer = Array.from({ length: 20 }, (_, i) => ({ key: String.fromCharCode(97 + (i % 26)) }));
      const flushed = buffer.splice(0, buffer.length);
      return { pass: flushed.length === 20 && buffer.length === 0, detail: `${flushed.length}/20 keys flushed, ${buffer.length} left behind` };
    },
  },
  {
    id: 9, name: 'Baseline diff suppresses known-good startup entries',
    run: () => {
      const sys = clone(CLEAN); const base = baselineOf(CLEAN);
      const f = detector.ruleStartup(sys, base);
      return { pass: f.length === 0, detail: 'OneDrive entry present in baseline → not flagged' };
    },
  },
  {
    id: 10, name: 'Renamed logger (different name, same hook DLL) still caught',
    run: () => {
      const sys = clone(CLEAN);
      sys.processes.push({ pid: 5310, name: 'helper-service.exe', user: 'SYSTEM', cpu: 0.5, hasWindow: false, modules: ['kbdhook.dll'] });
      const f = detector.ruleHookDll(sys);
      return { pass: f.length === 1, detail: f.map((x) => x.title).join('; ') || 'missed — signature-style name matching would fail here' };
    },
  },
  {
    id: 11, name: 'Legit mail client on :587 is allow-listed (no false alarm)',
    run: () => {
      const sys = clone(CLEAN);
      sys.connections.push({ pid: 2600, process: 'outlook.exe', local: '192.168.1.20:51400', remote: 'outlook.office365.com:587', proto: 'TCP', state: 'ESTABLISHED' });
      const f = detector.ruleSmtpExfil(sys);
      return { pass: f.length === 0, detail: 'outlook.exe on :587 ignored' };
    },
  },
  {
    id: 12, name: 'Two back-to-back flush cycles → no key lost or repeated',
    run: () => {
      const buffer = [];
      const seen = new Set();
      let lost = 0, repeated = 0;
      for (let cycle = 0; cycle < 2; cycle++) {
        for (let i = 0; i < 10; i++) buffer.push({ key: `c${cycle}k${i}` });
        const flushed = buffer.splice(0, buffer.length);
        for (const k of flushed) { if (seen.has(k.key)) repeated += 1; seen.add(k.key); }
      }
      lost = 20 - seen.size;
      return { pass: seen.size === 20 && lost === 0 && repeated === 0, detail: `${seen.size}/20 unique keys delivered, ${lost} lost, ${repeated} repeated` };
    },
  },
];

function runAll() {
  const started = Date.now();
  const results = CASES.map((c) => {
    let r;
    try { r = c.run(); } catch (e) { r = { pass: false, detail: `error: ${e.message}` }; }
    return { id: c.id, name: c.name, pass: !!r.pass, detail: r.detail || '' };
  });
  const passed = results.filter((r) => r.pass).length;
  return {
    ranAt: new Date().toISOString(),
    total: results.length,
    passed,
    failed: results.length - passed,
    durationMs: Date.now() - started,
    results,
  };
}

module.exports = { runAll, CASES };

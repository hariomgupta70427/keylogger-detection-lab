// The detector — four rules, each matching a trace the attack leaves behind
// (report slide 4). Every rule is a real function over the simulated system
// state, and every scan is persisted to detection.db.
//
//   RULE-HOOK-DLL   HIGH  no-window process with a keyboard-hook module
//   RULE-SMTP-EXFIL HIGH  live connection to 25/465/587 from a non-mail app
//   RULE-STARTUP    MED   Run-key / scheduled-task entry that is new vs baseline
//   BASELINE-DIFF         the mechanism: only report what is new vs the clean
//                         snapshot, which is what removed the false positives
// MITRE: T1056.001 (Input Capture: Keylogging) · T1041 (Exfiltration Over
// C2 Channel) · T1547.001 (Boot/Logon Autostart: Registry Run Keys)
const db = require('./db');
const sim = require('./sim');

const MAIL_PORTS = [25, 465, 587];
const MAIL_CLIENTS = ['outlook.exe', 'thunderbird.exe', 'mail.exe', 'evolution'];
const HOOK_MODULES = ['kbdhook.dll', 'hook.dll', 'keyhook.dll', 'setwindowshookex'];

function portOf(remote) {
  const m = String(remote || '').match(/:(\d+)$/);
  return m ? Number(m[1]) : null;
}

function ruleHookDll(system) {
  const findings = [];
  for (const p of system.processes) {
    const hookMod = (p.modules || []).find((m) => HOOK_MODULES.includes(m.toLowerCase()));
    if (!p.hasWindow && hookMod) {
      findings.push({
        rule: 'RULE-HOOK-DLL',
        severity: 'HIGH',
        title: `Hidden process holding a keyboard-hook module: ${p.name} (pid ${p.pid})`,
        evidence: `pid ${p.pid} · ${p.name} · user ${p.user} · no window · loaded module ${hookMod} · CPU ${p.cpu}%`,
        mitre: 'T1056.001',
      });
    }
  }
  return findings;
}

function ruleSmtpExfil(system) {
  const findings = [];
  for (const c of system.connections) {
    const port = portOf(c.remote);
    if (!MAIL_PORTS.includes(port)) continue;
    if (MAIL_CLIENTS.includes(String(c.process || '').toLowerCase())) continue;
    findings.push({
      rule: 'RULE-SMTP-EXFIL',
      severity: 'HIGH',
      title: `Outbound mail-port connection from a non-mail program: ${c.process} → :${port}`,
      evidence: `${c.process} (pid ${c.pid}) · ${c.local} → ${c.remote} · ${c.proto} ${c.state} · not a mail client`,
      mitre: 'T1041',
    });
  }
  return findings;
}

function ruleStartup(system, baseline) {
  const findings = [];
  const known = new Set((baseline?.startup || []).map((s) => `${s.location}|${s.name}`));
  for (const s of system.startup) {
    if (!known.has(`${s.location}|${s.name}`)) {
      findings.push({
        rule: 'RULE-STARTUP',
        severity: 'MED',
        title: `New autostart entry: ${s.name}`,
        evidence: `${s.location} · ${s.name} = ${s.value} · not present in the clean baseline`,
        mitre: 'T1547.001',
      });
    }
  }
  return findings;
}

// Baseline diff across processes + connections too: only what's new is
// reported, so known-good items never raise a finding.
function ruleBaselineDiff(system, baseline) {
  if (!baseline) return [];
  const findings = [];
  const knownProcs = new Set((baseline.processes || []).map((p) => `${p.pid}|${p.name}`));
  for (const p of system.processes) {
    if (knownProcs.has(`${p.pid}|${p.name}`)) continue;
    // Already covered by the hook rule when it is a hook process; the diff
    // rule only adds genuinely new, unexplained processes.
    if ((p.modules || []).some((m) => HOOK_MODULES.includes(m.toLowerCase()))) continue;
    findings.push({
      rule: 'BASELINE-DIFF',
      severity: 'MED',
      title: `New process since clean baseline: ${p.name} (pid ${p.pid})`,
      evidence: `pid ${p.pid} · ${p.name} · user ${p.user} · first seen after baseline ${baseline.takenAt}`,
      mitre: 'T1056.001',
    });
  }
  return findings;
}

function runScan() {
  const started = Date.now();
  const system = JSON.parse(JSON.stringify(sim.state.system));
  const baseline = sim.state.baseline ? JSON.parse(JSON.stringify(sim.state.baseline)) : null;
  const findings = [
    ...ruleHookDll(system),
    ...ruleSmtpExfil(system),
    ...ruleStartup(system, baseline),
    ...ruleBaselineDiff(system, baseline),
  ];
  const verdict = findings.length === 0 ? 'CLEAN' : 'SUSPICIOUS';
  const durationMs = Date.now() - started;
  const scanId = db.saveScan({ verdict, findings, durationMs });
  const scan = {
    id: scanId,
    scannedAt: new Date().toISOString(),
    verdict,
    findings,
    durationMs,
    baselineUsed: baseline ? baseline.takenAt : null,
  };
  sim.state.lastScan = { id: scanId, verdict, findingsCount: findings.length, scannedAt: scan.scannedAt };
  return scan;
}

module.exports = { runScan, ruleHookDll, ruleSmtpExfil, ruleStartup, ruleBaselineDiff, MAIL_PORTS, MAIL_CLIENTS };

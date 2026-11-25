// detection.db — every scan and finding is stored (SQLite), so results are
// reproducible, not anecdotal. Mirrors the report's detection.db.
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

const DB_PATH = process.env.DETECTION_DB || path.join(__dirname, '..', 'detection.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    findings_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    med_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,
    mitre TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS flush_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flushed_at TEXT NOT NULL,
    keys_flushed INTEGER NOT NULL,
    bytes_flushed INTEGER NOT NULL,
    channel TEXT NOT NULL
  );
`);

function saveScan({ verdict, findings, durationMs }) {
  const now = new Date().toISOString();
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const med = findings.filter((f) => f.severity === 'MED').length;
  const insertScan = db.prepare(
    'INSERT INTO scans (scanned_at, verdict, findings_count, high_count, med_count, duration_ms) VALUES (?, ?, ?, ?, ?, ?)'
  );
  const info = insertScan.run(now, verdict, findings.length, high, med, durationMs);
  const scanId = info.lastInsertRowid;
  const insertFinding = db.prepare(
    'INSERT INTO findings (scan_id, rule, severity, title, evidence, mitre) VALUES (?, ?, ?, ?, ?, ?)'
  );
  for (const f of findings) {
    insertFinding.run(scanId, f.rule, f.severity, f.title, f.evidence, f.mitre);
  }
  return scanId;
}

function listScans(limit = 25) {
  const scans = db
    .prepare('SELECT * FROM scans ORDER BY id DESC LIMIT ?')
    .all(limit)
    .map((s) => ({ ...s, findings: [] }));
  if (scans.length === 0) return scans;
  const ids = scans.map((s) => s.id);
  const placeholders = ids.map(() => '?').join(',');
  const rows = db
    .prepare(`SELECT * FROM findings WHERE scan_id IN (${placeholders}) ORDER BY id ASC`)
    .all(...ids);
  const byScan = new Map(scans.map((s) => [s.id, s]));
  for (const r of rows) byScan.get(r.scan_id).findings.push(r);
  return scans;
}

function getScan(id) {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  if (!scan) return null;
  scan.findings = db.prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC').all(id);
  return scan;
}

function recordFlush({ keys, bytes, channel }) {
  db.prepare('INSERT INTO flush_log (flushed_at, keys_flushed, bytes_flushed, channel) VALUES (?, ?, ?, ?)')
    .run(new Date().toISOString(), keys, bytes, channel);
}

function flushStats() {
  const row = db
    .prepare('SELECT COUNT(*) AS cycles, COALESCE(SUM(keys_flushed), 0) AS keys_total FROM flush_log')
    .get();
  return { cycles: row.cycles, keysTotal: row.keys_total };
}

module.exports = { saveScan, listScans, getScan, recordFlush, flushStats };

// Keylogger Simulation & Detection Lab — backend.
// Educational demo built from the BHEL summer-training documents
// (Vanshika Tyagi, GTBIT). Everything is simulated: the "victim machine" is
// an in-memory model, captured keystrokes never leave the demo page, and the
// "exfiltrated" mail only ever lands in an on-screen outbox.
const express = require('express');
const path = require('node:path');
const sim = require('./src/sim');
const detector = require('./src/detector');
const testsuite = require('./src/testsuite');
const db = require('./src/db');

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/status', (req, res) => res.json(sim.publicStatus()));

app.post('/api/sim/start', (req, res) => {
  const r = sim.startSim(req.body || {});
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/sim/stop', (req, res) => {
  const r = sim.stopSim();
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/sim/keystroke', (req, res) => {
  const r = sim.ingestKeystroke(req.body || {});
  res.status(r.ok ? 200 : 400).json(r);
});

app.post('/api/sim/clipboard', (req, res) => {
  res.json(sim.ingestClipboard(req.body || {}));
});

app.post('/api/sim/screenshot', (req, res) => {
  res.json(sim.captureShot(req.body || {}));
});

app.post('/api/sim/flush', (req, res) => {
  if (!sim.state.sim.running && sim.state.sim.buffer.length === 0) {
    return res.status(400).json({ ok: false, error: 'Nothing to flush.' });
  }
  res.json({ ok: true, entry: sim.flush('manual') });
});

app.get('/api/sim/outbox', (req, res) => {
  res.json({
    outbox: sim.state.sim.outbox,
    clipboardLog: sim.state.sim.clipboardLog,
    shots: sim.state.sim.shots,
    buffer: sim.state.sim.buffer,
  });
});

app.post('/api/detect/baseline', (req, res) => {
  res.json({ ok: true, baseline: sim.takeBaseline() });
});

app.post('/api/detect/scan', (req, res) => {
  res.json({ ok: true, scan: detector.runScan() });
});

app.get('/api/detect/scans', (req, res) => {
  res.json({ scans: db.listScans(25) });
});

app.get('/api/detect/scans/:id', (req, res) => {
  const scan = db.getScan(Number(req.params.id));
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ scan });
});

app.post('/api/tests/run', (req, res) => {
  res.json({ ok: true, suite: testsuite.runAll() });
});

app.post('/api/lab/reset', (req, res) => {
  res.json(sim.resetLab());
});

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'keylogger-lab' }));

app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Keylogger Simulation & Detection Lab listening on :${PORT}`);
  console.log('Lab-only simulation: no real keystrokes, processes or mail involved.');
});

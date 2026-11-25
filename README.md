# Keylogger Simulation & Detection Lab

Educational demo built from the BHEL summer-training documents —
**Keylogger Simulation & Detection Tool** by Vanshika Tyagi, B.Tech IT Sem VII,
GTBIT (GGSIPU), BHEL Corporate Digital Transformation, New Delhi
(guide: Mr. Bharat Panwar, Summer Training 2026).

## What it is

A working, presentable demo of **every part** of the two documents:

- **Simulation** — a sandboxed "victim VM" (LAB-VM-01) with demo login forms
  and a notepad. Start the simulated keylogger and everything typed in those
  demo fields is captured into an in-memory buffer, flushed on a timer, and
  "exfiltrated" over simulated SMTP_SSL :465 into an on-screen outbox.
  Persistence (Run key), clipboard logging and screenshot capture are
  toggleable. Safety guards from the report are enforced in code: lab-only,
  no plain text on disk, Esc stop hotkey, 2-hour hard stop.
- **Detection** — the four rules from the report, implemented as real
  functions over the simulated system state: RULE-HOOK-DLL (HIGH),
  RULE-SMTP-EXFIL (HIGH), RULE-STARTUP (MED) and BASELINE-DIFF (only what's
  new vs the clean snapshot is reported). Every scan is saved to
  `detection.db` (SQLite), so results are reproducible.
- **Test suite** — the 12 lab test cases. Each builds its own sandboxed
  system state, runs the real detector rules and asserts the outcome.
- **Learn** — what a keylogger is, software/hardware types, real-world
  incidents (Zeus, GameOver Zeus, HawkEye, Agent Tesla, 2010 ATM heist),
  detection & countermeasures, the legal line in India (IT Act s.43/66/66C,
  DPDP 2023, CERT-In 6-hour reporting) and the MITRE mapping
  (T1056.001 / T1041 / T1547.001).
- **Architecture** — the nine-step workflow and the tools (Python 3.10+,
  pynput, smtplib, threading, SQLite).

## Honest limits

This is a **web demo of a simulation**. It does not install a keyboard hook,
read a real process table, or send real email — the "victim machine" is a
model, and the detector reads that model. The numbers on the Test Suite tab
are produced live by running the suite; the BHEL lab measurements (12/12,
0 false alarms, 0.7% CPU) are quoted from the report and labelled as such.

## Run locally

```bash
npm install
npm start   # http://localhost:3000
```

## Deploy (Render, free tier)

Push this repo to GitHub, then create a Web Service from `render.yaml`
(or "New → Web Service", build `npm install`, start `npm start`).
The free tier sleeps after inactivity; the first load after sleep takes ~30s.

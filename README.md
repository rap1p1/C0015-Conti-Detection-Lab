# C0015 Detection Lab

Evidence-driven reconstruction of [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/)
(Conti/Bazar intrusion, DFIR Report *CONTInuing the Bazar Ransomware Story*, 2021-11-29) for detection
engineering and incident-response training on an owned homelab. The lab replays the intrusion with real
Windows/AD/network telemetry, lab-safe payload surrogates, an internal C2 simulator, explicit artifact
handoffs between stages, and a detection-rule suite (R01-R21) validated on recorded runs.

## Campaign chain — original tools vs lab tools

| Stage | Technique (MITRE) | Original tool (DFIR report) | Lab surrogate / tool | Telemetry anchor | Detection |
|---|---|---|---|---|---|
| S1 | T1204.002/T1059.005 → T1218.005/T1218.010/T1105 | Word macro → HTA → regsvr32 Bazar DLL | `c0015_final3.docm` (macro **self-writes** config/HTA/beacon) + `c0015_143_surrogate.dll` | Sysmon E1 office→mshta→regsvr32, E11 macro writes | R01-R08 |
| S2-S3 | T1071.001, T1016 | Bazar C2 / Cobalt Strike | `c0015_beacon.ps1` (phase3) → C2-SIM :8080 | E1/E3 + `register` | R05/R06/R09 |
| S4-S5 | T1057/T1069/T1482/T1016/T1018/T1135 | AdFind, net, nltest, PowerView (Invoke-ShareFinder) | `scripts/runbooks/c0015-phase2.json` | E1 beacon→cmd→tool | R10-R13 |
| S7 | T1078 | valid accounts | `C0015\it.admin` | Security 4624/4672 | R14a/R14b |
| S7b | T1003.001 | ProcessHacker (dump) | mimikatz-style surrogate (signed-off, no secrets) | Sysmon E10 0x1010 | R15 |
| S8a | T1570/T1105 | SMB **C$** + `143.dll` copy | beacon-side copy + `143.dll` → FS01 `C:\C0015` | Security 5145 + E11 | R16 |
| S8b | T1047/T1218.011 | `wmic ... rundll32 ... 143.dll` | space-form `rundll32.exe ... LabEntry` (WMI) | E1 wmiprvse→rundll32 | R17 |
| S9 | T1071.001 | Cobalt Strike session 2 | beacon (phase7-session2, FS01) | E3 :8080 + receipt ART-07-01 | R18 |
| S10 | T1005/T1039/T1074.001 | ShareFinder re-run, staging | beacon UNC collection → `C:\C0015\collect\` | E11 + S5145 | R16 |
| S11a/b | T1567.002/T1030 | **rclone → MEGA** (two rounds) | real rclone → **local WebDAV sink** (:9001) | E1 rclone, E3 :9001, receipt ART-09-01 | R06/R09 |
| S12 | T1021.001 | RDP to backup server (day 2) | RDP `mstsc` + `cmdkey` | Security 4624 T3/T4/T10 | R19 |
| S13 | T1219.002 | AnyDesk in `Videos\`, ProcessHacker at `C:\` | real AnyDesk (lab-local use) + ProcessHacker (no dump) | E11 drop paths + E1 | R20 |
| S14 | T1486/T1083 | `locker.bat` + Conti (`-m -net -size 10 ...`) | `c0015_impact.ps1` **bounded** surrogate (reversible) | E11 bulk rename + note | R21 |
| S15 | E2E / IR exercise | — | orchestrator + ledger + scorecard ART-15-01 | evidence chain | — |

## Repository structure

```
phases/        phase1-initial-access | phase2-operator | phase3-final-campaign   (each with README)
docs/          canonical technical records (chain, runbook, architecture, telemetry comparison, C2 design)
detections/    rule suite R01-R21 (eql/ + README with full index, severity and stage mapping)
payloads/      lab tooling per chain stage (beacon, dll, hta, impact, docm, lsass, packaging)
scripts/       infrastructure: C2-SIM, watchdog, lab_tools (artifacts/receipts/score), runbooks, verify, preflight
configs/       agent/Sysmon configuration
evidence/      run ledger (only the latest validated run is retained) + artifacts
stage/         runtime files (generated docm, configs, tools) — gitignored; evidence copies live in evidence/
build/         served tool staging for the HTTP ..:8000 (gitignored)
```

## Detection suite

21 rules (R01-R21), Elastic EQL, deterministic `rule_id` (SHA-256 of the rule name) for
idempotent re-import. **High/alerting rules: R17 (WMI pivot), R18 (proxy→PS egress),
R21 (impact artifacts).** Medium: R14b, R15, R19, R20. All other rules are
low-severity building blocks (BB-ON) or suppressed. Full index, stage mapping and
run coverage: [detections/README.md](detections/README.md).

## Lab boundaries (current)

- Exfiltration stops at the internal sink — no public cloud (MEGA/Telegram never used).
- Impact is a bounded, allowlist-root-capped, reversible surrogate — no real encryption,
  no self-propagation.
- AnyDesk usage in the final campaign was lab-internal; the public relay is not a C2 channel.
- No secrets in repo/logs; per-run credentials stay in gitignored `stage/`.

## Key documents

- [docs/attack-chain-plan.md](docs/attack-chain-plan.md) — the canonical S1-S15 chain + fidelity blocks.
- [docs/attack-runbook.md](docs/attack-runbook.md) — operator runbook (per-stage commands).
- [docs/architecture.md](docs/architecture.md) — lab topology, channels, Elastic/Fleet setup.
- [docs/correlation-architecture.md](docs/correlation-architecture.md) — telemetry correlation design.
- [docs/telemetry-comparison-c0015-vs-lab.md](docs/telemetry-comparison-c0015-vs-lab.md) — event-level parity.
- [docs/payloads-and-c2.md](docs/payloads-and-c2.md) — payload/C2 design notes.
- `phases/phaseN/` — per-phase plans, run records and recipes.
- [evidence/run-ledger/](evidence/run-ledger/) — schema + the latest validated run (RUN-20261002-05).
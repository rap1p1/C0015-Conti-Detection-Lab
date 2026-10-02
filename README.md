# C0015 Detection Lab

Evidence-driven reconstruction of [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/)
(Conti/Bazar intrusion, DFIR Report *CONTInuing the Bazar Ransomware Story*, 2021-11-29) as a detection
engineering and incident-response exercise on an owned homelab. The lab reproduces the intrusion end to
end with real Windows/AD/network telemetry, benign payload surrogates, an internal C2 simulator,
artifact-verified stage handoffs, and a detection-rule suite validated against the telemetry of a
recorded run.

## Campaign chain — original tools and lab surrogates

| Stage | Technique (MITRE) | Original tool (report) | Lab surrogate | Telemetry anchor | Detection |
|---|---|---|---|---|---|
| S1 | T1204.002/T1059.005 → T1218.005/T1218.010/T1105 | Word macro → HTA → regsvr32 Bazar DLL | entry document `c0015_entry.docm` (macro self-writes config/HTA/beacon) + `c0015_143_surrogate.dll` | Sysmon E1 office→mshta→regsvr32, E11 macro writes | R01-R08 |
| S2-S3 | T1071.001, T1016 | Bazar C2 / Cobalt Strike | `c0015_beacon.ps1` (phase3) → C2-SIM :8080 | E1/E3 + `register` | R05/R06/R09 |
| S4-S5 | T1057/T1069/T1482/T1016/T1018/T1135 | AdFind, net, nltest, PowerView (Invoke-ShareFinder) | `scripts/runbooks/c0015-phase2.json` | E1 beacon→cmd→tool | R10-R13 |
| S7 | T1078 | valid accounts | `C0015\it.admin` | Security 4624/4672 | R14a/R14b |
| S7b | T1003.001 | ProcessHacker (dump) | mimikatz-style surrogate (signed off, no secrets) | Sysmon E10 0x1010 | R15 |
| S8a | T1570/T1105 | SMB **C$** + `143.dll` copy | beacon-side copy + `143.dll` → FS01 `C:\C0015` | Security 5145 + E11 | R16 |
| S8b | T1047/T1218.011 | `wmic ... rundll32 ... 143.dll` | space-form `rundll32.exe ... LabEntry` (WMI) | E1 wmiprvse→rundll32 | R17 |
| S9 | T1071.001 | Cobalt Strike session 2 | beacon (phase7-session2, FS01) | E3 :8080 + receipt ART-07-01 | R18 |
| S10 | T1005/T1039/T1074.001 | ShareFinder re-run, staging | beacon UNC collection → `C:\C0015\collect\` | E11 + S5145 | R16 |
| S11a/b | T1567.002/T1030 | **rclone → MEGA** (two rounds) | real rclone → **local WebDAV sink** (:9001) | E1 rclone, E3 :9001, receipt ART-09-01 | R06/R09 |
| S12 | T1021.001 | RDP to the backup server (day 2) | RDP `mstsc` + `cmdkey` | Security 4624 T3/T4/T10 | R19 |
| S13 | T1219.002 | AnyDesk in `Videos\`, ProcessHacker at `C:\` | real AnyDesk (lab-internal) + ProcessHacker | E11 drop paths + E1 | R20 |
| S14 | T1486/T1083 | `locker.bat` + Conti (`-m -net -size 10 ...`) | `c0015_impact.ps1` bounded surrogate (reversible) | E11 bulk rename + note | R21 |

## Repository structure

```
phases/      phase1-initial-access | phase2-operator | phase3-final-campaign   (each with its own README)
docs/        canonical technical records (chain, runbook, architecture, correlation, C2 design)
detections/  rule suite R01-R21 (eql/ + README: full index, severity and stage mapping)
payloads/    lab tooling per chain stage (beacon, dll, hta, impact, docm, lsass, packaging)
scripts/     infrastructure: C2-SIM, watchdog, evidence toolkit, runbooks, fixtures, tests
configs/     agent/Sysmon configuration
evidence/    run ledger (schema + the reference run) and stage artifacts
stage/       runtime files (generated document, per-run configs, tools) — gitignored
```

## Detection engineering

Twenty-one Elastic EQL rules (R01-R21) implement a layered detection model that mirrors the
intrusion chronology: initial access (R01-R08), beacon live-off-the-land activity (R09-R13),
credential access and lateral movement (R14a-R18), and remote-access/exfiltration/impact
(R19-R21). The alerting set — **R17** (WMI pivot to an unsigned module), **R18** (proxy-spawned
beacon egress) and **R21** (impact artifacts) — is high severity; the remaining rules operate as
correlation building blocks with suppression on noisy sources. Every rule uses a deterministic
`rule_id` (SHA-256 of the rule name) and is written without environment-specific values.
Full index, stage mapping and run coverage: [detections/README.md](detections/README.md).

## Confinement

- Exfiltration terminates at an internal sink; no public cloud service is used.
- Impact is a bounded, allowlist-capped and reversible surrogate — no real encryption,
  no self-propagation.
- Remote-access software runs lab-internal only; its relay channel is never used as C2.
- Secrets are never stored in the repository; per-run credentials remain in gitignored
  runtime directories.

## Key documents

- [docs/attack-chain-plan.md](docs/attack-chain-plan.md) — the canonical S1-S15 chain and fidelity blocks.
- [docs/attack-runbook.md](docs/attack-runbook.md) — operator runbook with per-stage procedures.
- [docs/architecture.md](docs/architecture.md) — lab topology, channels, Elastic/Fleet ingestion.
- [docs/correlation-architecture.md](docs/correlation-architecture.md) — telemetry correlation design.
- [docs/telemetry-comparison-c0015-vs-lab.md](docs/telemetry-comparison-c0015-vs-lab.md) — event-level parity.
- [docs/payloads-and-c2.md](docs/payloads-and-c2.md) — payload and C2 design.
- `phases/phaseN/` — per-phase plans and run records.
- [evidence/run-ledger/](evidence/run-ledger/) — ledger schema and the reference run.
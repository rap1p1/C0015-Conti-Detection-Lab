# Phase 3 — collection, remote access and impact (S10–S14)

The campaign ends at bounded impact, S14. Post-run validation/S15, recovery and
cleanup are separate. RUN-09 is the latest reference; RUN-07 records rule tuning.

| Stage | Implemented behavior | Evidence and coverage |
|---|---|---|
| S10 | WS01 operator collects through FS01 C$, stages 11 files/309 B | E11/5145 and ART-08-01; R16 covers admin-share access checks |
| S11a/b | WS01 rclone → internal WebDAV :9001, two rounds | E1/E3 + ART-09-01 per-file equality; R24 |
| S12 | Operator-host RDP to FS01 | 4624 T10 → 4634 T10 LogonId join; R19 positive in 06–09 |
| S13 | AnyDesk drop/execution and ProcessHacker deployment surface | E11/E1 as recorded; R20 covers remote-access software, not ProcessHacker |
| S14 | FS01 dummy-corpus transformation and note spread | E11, R22/R23, ART-14-01 and recovery output |

Receipts compare the observed sink set against the manifest by name, size and
content SHA-256. The manifest-document hash is a separate canonical integrity key.
An E3 connection does not establish cloud exfiltration, bandwidth rate or completion.
Historical MEGA transfer is replaced by internal WebDAV. Check each replay's order:
RDP was not between the transfer rounds in every run.

RDP Type 4 is batch, not interactive RDP. All retained runs now have a joined T10
logoff; 4778 reconnect/4779 disconnect is separately unverified, so S12 remains PARTIAL.
AnyDesk vendor-relay observations do not make it the simulator's C2 channel.
The ProcessHacker surface does not prove LSASS extraction.

RUN-05 used an earlier one-directional impact comparison; 06–09 record 30
bidirectional mismatches before rollback and content/hash equality after recovery.
Note-spread detection is impact-adjacent evidence, not proof of encryption.

- [Historical final-stage plan](final-campaign-plan.md)
- [RUN-05 detection notes](detection-run-20261002-05.md)
- [Latest report](../../reports/reference-run-20261002-09.md), [evidence](../../evidence/runs/), and [rules](../../detections/README.md)
- [Acceptance tooling](../../scripts/README.md)

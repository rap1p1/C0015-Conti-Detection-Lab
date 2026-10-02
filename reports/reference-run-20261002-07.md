# Reference Run Report — RUN-20261002-07 (campaign S1–S14, tuned rules)

Window: 2026-10-02 08:50:00Z – 09:15:00Z. Ledger: `evidence/runs/RUN-20261002-07/`.

Structure: the **campaign chain is S1–S14** (ending at bounded impact). This report's
remaining sections are **Validation & Detection Coverage** and **Recovery & Cleanup** —
Detection-Engineer evaluation, not simulated campaign behavior.

## Campaign chain summary (S1–S14)

| Stage | Evidence (key) |
|---|---|
| S1 entry | macro self-write (c0015wf.log 08:54:56Z) → mshta → regsvr32 (entity chain) → register `S1-353be732c7d5d5d2` 08:55:01Z |
| S4–S5 discovery/share | runbook batch (30+ tasks); net view es_id `AaD706iPmO7CP6QKbU0_` 08:55:00Z |
| S7b LSASS surface | E10 `AaD71qiPmO7CP6QmeEts` 08:58:21Z grant 0x1010 |
| S8a/S8b handoff+pivot | 5145 C$; rundll32 `AaD716iPmO7CP6QUe7aE` 08:59:29Z (parent=WmiPrvSE, LabEntry); E7 unsigned `AaD716iPmO7CP6QUe7aI` |
| S9 session-2 | entity-owned E3 08:59:33Z; receipt `ART-07-01-c0dfc1fa` 08:59:31Z |
| S10 collection | ART-08-01 manifest (11 files / 309 B) |
| S11a/b transfer | rclone rounds 1+2 → sink (22 files); receipts 11/11 per-file equality |
| S12 RDP | **interactive logon (T10)** `AaD72qiPmO7CP6S6j0bF` 09:03:26.968Z, it.admin, logonid 0x3a89180; R19 alerts 09:03:38Z |
| S13 remote tools | AnyDesk drop→run (09:04:42→09:05:13), ProcessHacker drop 09:05:07 |
| S14 impact | 15 files; Verify 30 bidirectional mismatches → Rollback → hash-equal |

## Validation & Detection Coverage (post-run, Detection-Engineer work)

Acceptance: `scripts/verify/verify_final_phases.py RUN-20261002-07` → **ACCEPTED** (entity
joins, E7 continuity, S9 entity-owned E3, per-file sink equality, T10 + R19 alerts,
artifact hashes canonical).

Alert volume (stored docs in window; unique-activity where cardinality applies):

| Rule | Docs | Unique activity | Note |
|---|---|---|---|
| R06 egress | 375 | **11 entities** | polling loop; entity suppression in place |
| R16 admin share | 184 | — (per-logon context) | suppression host+SubjectLogonId+ShareName 5m configured; docs remain per-sweep copies (upper bound) |
| R14b elevated | 169 | — (per-logon context) | suppression host+SubjectLogonId 5m configured; same caveat |
| R17 WMI pivot | 3 | **1 sequence** | single activity |
| R18 proxy egress | 6 | **2 activities** | second-session egress |
| R22 note class | 3 | 3 creates | building block |
| **R23 note spread** | **1** | **1 activity** | **new alerting rule fired live** (3 distinct paths, one process) |
| R24 transfer tool | 6 | 2 rounds + polls | new building block |
| R19 RDP | 2 | 1 T10 logon | true positive |

Compared with RUN-20261002-06: the tuned rules added coverage (R22/R23/R24) without
removing any stage signal; R16 stored docs 273→184 with the new suppression config.

Gaps (unchanged): S12 session lifetime not captured; E7 hash field present at file.hash.sha256 (ECS; equals the artifact hash) in-axis;
rename attribution limited (no delete auditing); rclone evidence = events + receipts.

## Recovery & Cleanup

- Bounded impact fully reversed: `Rollback OK`, post-restore `Verify` = **bidirectional
  hash-equal** (ART-14-01-RUN07).
- Run cleanup: beacons, Word, mshta, AnyDesk/ProcessHacker terminated; rclone sink and
  servers stopped after evidence collection.
- Alert hygiene: the pre-run backlog was cleared (0 open at run start); the alert
  volume above is from this run's window.

## References

- Ledger + artifacts: `evidence/runs/RUN-20261002-07/`
- Rule index: `detections/README.md`; verifier: `scripts/verify/verify_final_phases.py`
- Detailed runbook: `docs/attack-runbook.md`

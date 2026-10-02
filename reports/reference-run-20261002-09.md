# Reference Run Report — RUN-20261002-09 (S6 + S12 lifecycle validation)

Window: 2026-10-02 12:55:00Z – 13:35:00Z. Ledger: `evidence/runs/RUN-20261002-09/`.

## Campaign chain (S1–S14)

| Stage | Evidence |
|---|---|
| S1 entry | macro self-write (wf log 12:56:14Z) → mshta → regsvr32 → beacon; register 44233104 12:56:19Z |
| S4–S5 discovery | 8-task batch executed |
| **S6 target selection** | **EXECUTED** — server-side orchestration selected FS01 (13:12:37Z) → `ART-06-02-RUN09.json` (decision artifact) |
| S7/S7b | elevate (wmic ReturnValue 0) → it.admin beacon; E10 surrogate 0x1010 |
| S8a/S8b | 5145 C$; rundll32 (par WmiPrvSE, LabEntry) ~13:15:0xZ + E7 (hash at file.hash.sha256) |
| S9 session-2 | register `7e715c9a` 13:15:10Z + receipt `ART-07-01-7e715c9a.json` |
| S10 | ART-08-01 manifest (11 files / 309 B) |
| S11a/S11b | rclone rounds (E1 13:17:07Z / 13:18:51Z) → sink 22 files; receipts 11/11 full-set |
| S12 RDP | **T10 interactive logon 13:17:54.978Z** (TargetLogonId 0x4cc3dae); R19 alerts 13:18:45Z; session `rdp-tcp#9 Conn` captured; **end = 4634 logoff 13:18:22Z** (ingested, local=ES 87x). 4779 (disconnect) not generated locally (audit effective) - generation gap; 4778 (reconnect) n/a |
| S13 | AnyDesk drop→run (13:19:49→13:20:16), ProcessHacker drop 13:19:59 |
| S14 impact | 15 files; Verify 30 bidirectional mismatches → Rollback → hash-equal |

## Validation & Detection Coverage

`python scripts/verify/verify_final_phases.py RUN-20261002-09` → **ACCEPTED** (5/5 runs).
Coverage: R22 note-class, **R23 alert live (3 distinct paths, one entity)**, R24 transfer-tool.
Offline tests: 20/20 OK (task sequence updated for the S6 selection step).

## Limitations — status update

- **S6**: resolved — orchestration decision executed and artifacted (RUN-09).
- **S12**: partially resolved — T10 + session state captured; 4778/4779 disconnect
  events not generated (abrupt client close); the gap is recorded, not papered over.
- **RUN-09 provenance**: every stage reference carries real ids/timestamps where the
  live event was fetched; timing annotations are honest (multiple beacon relaunches
  caused by the short `loop_count` in the first guest config are documented).

## Recovery & Cleanup

- Impact fully reversed: `Rollback OK`, post-restore `Verify` = bidirectional hash-equal.
- Beacon/tool processes terminated after evidence; sink and servers stopped.

## References

- Ledger + artifacts: `evidence/runs/RUN-20261002-09/`
- Rule index: `detections/README.md` · Verifier: `scripts/verify/verify_final_phases.py`

# Reference Run Report — RUN-20261002-09 (S6 + S12 lifecycle validation)

Window: 2026-10-02 12:55:00Z – 13:35:00Z. Ledger: [evidence/runs/RUN-20261002-09/](../evidence/runs/RUN-20261002-09/).

## Campaign chain (S1–S14)

| Stage | Evidence |
|---|---|
| S1 entry | macro self-write (wf log 12:56:14Z) → mshta → regsvr32 → beacon; register 44233104 12:56:19Z |
| S4–S5 discovery | 8-task batch executed |
| **S6 target selection** | **EXECUTED** — server-side decision for the fixed scenario target FS01 (13:12:37Z); discovery-derived selection is not established → `ART-06-02-RUN09.json` (decision artifact) |
| S7/S7b | elevate (wmic ReturnValue 0) → it.admin beacon; E10 surrogate 0x1010 |
| S8a/S8b | 5145 C$; rundll32 (par WmiPrvSE, LabEntry) **13:15:05.678Z** E1 `AaD8waiPmO7CP6YYUlik` + **13:15:05.702Z** E7 `AaD8waiPmO7CP6YYUlio` (hash at file.hash.sha256) |
| S9 session-2 | register `7e715c9a` 13:15:10Z + receipt `ART-07-01-7e715c9a.json` |
| S10 | ART-08-01 manifest (11 files / 309 B) |
| S11a/S11b | rclone rounds (E1 13:17:07Z / 13:18:51Z) → sink 22 files; receipts 11/11 full-set |
| S12 RDP | **T10 interactive logon 13:17:54.978Z** (TargetLogonId 0x4cc3dae); R19 alerts 13:18:45Z; session `rdp-tcp#9 Conn`; **end = 4634 logoff 13:18:36Z joined by TargetLogonId (0x4cc3dae, Type 10)** (ingested; local=ES count parity 87/87, not per-event reconciliation). 4779 (disconnect)/4778 (reconnect): not separately verified |
| S13 | AnyDesk drop→run (13:19:49→13:20:16), ProcessHacker drop 13:19:59 |
| S14 impact | 15 files; Verify 30 bidirectional mismatches → Rollback → hash-equal |

## Validation & Detection Coverage

`python scripts/verify/verify_final_phases.py RUN-20261002-09` → **ACCEPTED** (5/5 runs).
Coverage: R22 note-class, **R23 alert live (3 distinct paths, one entity)**, R24 transfer-tool.
Offline tests: 20/20 OK (task sequence updated for the S6 selection step).

## Limitations — status update

- **S6**: fixed-scenario FS01 decision executed and artifacted (RUN-09); not a discovery-derived selection claim. 05–08 retain NOT RUN.
- **S12**: T10 logon, session snapshot and same-LogonId T10 logoff are verified. **4778 = reconnect; 4779 = disconnect**; these transitions are distinct from logoff and are not separately verified. The stage remains PARTIAL. Count parity is not per-event reconciliation, and absent disconnect records do not establish a cause.
- **RUN-09 provenance**: every stage reference carries real ids/timestamps where the
  live event was fetched; multiple beacon registrations/relaunches are recorded and must be reconstructed as separate segments. Older run notes attributed relaunches to guest loop-count behavior; that is not a general statement about current source, where loop_count is advisory.

## Recovery & Cleanup

- Impact fully reversed: `Rollback OK`, post-restore `Verify` = bidirectional hash-equal.
- Beacon/tool processes terminated after evidence; sink and servers stopped.

## References

- Ledger + artifacts: [evidence/runs/RUN-20261002-09/](../evidence/runs/RUN-20261002-09/)
- Rule index: [detections/README.md](../detections/README.md) · Verifier: [scripts/verify/verify_final_phases.py](../scripts/verify/verify_final_phases.py)


## RDP lifecycle provenance update

The current committed ledger records a same-FS01 **Type-10** logon-to-logoff join:

| Record | UTC event time | Elasticsearch ID |
|---|---|---|
| 4624 logon | 2026-10-02T13:17:54.978Z | `AaD8w6iPmO7CP6bCX9vl` |
| 4634 logoff | 2026-10-02T13:18:36.7Z | `AaD8xKiPmO7CP6ZkaTUg` |

Join: **4624.TargetLogonId == 4634.TargetLogonId (same host, same boot)**, with the same recorded account/logon type and logoff after logon.
This updates earlier “session lifetime not captured” wording; it does not establish
4778 reconnect or 4779 disconnect. S12 remains PARTIAL in the retained ledger.
The report uses the timestamp precision committed in the ledger.

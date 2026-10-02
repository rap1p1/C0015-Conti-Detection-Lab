# Reference Run Report — RUN-20261002-08 (campaign S1–S14, final tuned-rules run)

Window: 2026-10-02 09:33:00Z – 09:56:00Z. Ledger: [evidence/runs/RUN-20261002-08/](../evidence/runs/RUN-20261002-08/).

Structure: **campaign chain S1–S14** (ends at bounded impact), then **Validation &
Detection Coverage** and **Recovery & Cleanup** — Detection-Engineer work, not campaign
behavior.

## Campaign chain summary (S1–S14)

| Stage | Evidence (key) |
|---|---|
| S1 entry | macro self-write → mshta → regsvr32 (entity-joined) → register `93ddfe8b` 09:33:23Z (`S1-6eb01d7793ddfe8b`) |
| S4–S5 discovery/share | runbook batch; net view E1s |
| S7b LSASS surface | E10 lsass grant 0x1010 (no dump) |
| S8a/S8b handoff+pivot | 5145 C$; rundll32 (par=WmiPrvSE, LabEntry) **09:39:45.723Z**, E1 `AaD7-6iPmO7CP6Tu_Akw` (retried after config propagation); E7 unsigned |
| S9 session-2 | `S1-725a83c09ee55cdb` 09:39:46Z; receipt `ART-07-01-9ee55cdb` (run_id corrected to RUN-20261002-08) |
| S10 collection | ART-08-01 manifest (11 files / 309 B); 228×5145 C$ (collection reads target C$, not the ordinary shares) |
| S11a/b transfer | rclone rounds 1+2 → sink (22 files); receipts 11/11 full-set equality |
| S12 RDP | T10 logon **09:43:20.269Z** → T10 logoff **09:43:52.154Z**, joined by FS01 TargetLogonId **0x3da16ed**; R19 alert creation 09:43:37Z |
| S13 remote tools | AnyDesk drop→run (09:44:37→09:45:05), ProcessHacker drop 09:44:46 |
| S14 impact | 15 files; Verify 30 bidirectional mismatches → Rollback → hash-equal |

## Visual evidence

| Slot | Nội dung |
|---|---|
| SS01/SS05/SS06 (WS01) | network config, Sysmon active + E7/E10, audit policy/UTC — captured by the author (not stored in the repo) |
| SS22 (FS01) | impact Verify/Rollback output — captured by the author |
| SS28 | acceptance verifier output (RESULT: ACCEPTED) — captured by the author |
## Validation & Detection Coverage (post-run)

Acceptance: `python scripts/verify/verify_final_phases.py RUN-20261002-08` → **ACCEPTED**
(reverse entity joins, E7 continuity in-pivot, S9 dst :8080 + receipt content, S11
full-set equality with count, coverage R22/R23/R24, canonical hashes).

Alert volume (stored docs in window):

| Rule | Docs | Note |
|---|---|---|
| R06 egress | 862 | polling loop; unique-entity benchmark applies |
| R14b elevated | 198 | suppression host+SubjectLogonId active |
| R16 admin share | 167 | suppression host+SubjectLogonId+ShareName active |
| R10/R12 discovery | 54/33 | two rules reflect one activity |
| R17 WMI pivot | 3 | 1 sequence |
| R18 proxy egress | 6 | 2 activities |
| R22 note class | 3 | building block |
| **R23 note spread** | 1 | alerting rule fired live (3 distinct paths, one process.entity_id) |
| R24 transfer tool | 6 | rclone rounds |
| R19 RDP | 2 | T10 true positive |

R23 fired again with the entity-based grouping — the 3 note creates share one
`process.entity_id` (same-process context as named).

## Recovery & Cleanup

- Impact fully reversed: `Rollback OK`, post-restore `Verify` = bidirectional hash-equal.
- Beacons/Word/mshta/tools terminated; rclone sink and servers stopped after evidence.
- Screenshots are maintained by the author outside this snapshot. The previously referenced screenshot guide/assets directory is not committed; visual evidence is not required to resolve the event references in the ledger.

## References

- Ledger + artifacts: [evidence/runs/RUN-20261002-08/](../evidence/runs/RUN-20261002-08/)
- Rule index: [detections/README.md](../detections/README.md). Screenshot slots above refer to external author-held images, not an in-repository assets directory.


## Evidence scope

S6 is NOT RUN. S12 is PARTIAL only for separate 4778 reconnect/4779 disconnect
characterization; the joined logon-to-logoff records above are retained evidence.
Some older ledger notes still use superseded lifetime wording. E7 hashes are at
`file.hash.sha256`; missing-field claims from the old verifier are retracted.


## RDP lifecycle provenance update

The current committed ledger records a same-FS01 **Type-10** logon-to-logoff join:

| Record | UTC event time | Elasticsearch ID |
|---|---|---|
| 4624 logon | 2026-10-02T09:43:20.269Z | `AaD7_6iPmO7CP6VWCLR_` |
| 4634 logoff | 2026-10-02T09:43:52.154Z | `AaD7_6iPmO7CP6XMCgw6` |

Join: **4624.TargetLogonId == 4634.TargetLogonId (same host, same boot)**, with the same recorded account/logon type and logoff after logon.
This updates earlier “session lifetime not captured” wording; it does not establish
4778 reconnect or 4779 disconnect. S12 remains PARTIAL in the retained ledger.
The report uses the timestamp precision committed in the ledger.

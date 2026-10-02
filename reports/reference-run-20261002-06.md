# Reference Run Report — RUN-20261002-06 (final campaign, C0015, re-run)

Window: 2026-10-02 07:49:00Z – 08:12:00Z. Ledger: `evidence/runs/RUN-20261002-06/`.

## Summary

Re-run of the full campaign with the hardened tooling: canonical artifact hashes,
bidirectional impact Verify, env-only telemetry scripts, and the acceptance verifier.
Entry chain (S1) at 07:49:58Z; operator phase, WMI pivot and second-session receipt
(S9, ART-07-01-0e9f226e) by 07:53:02Z; collection, rclone rounds, remote-tool drops
and bounded impact with bidirectional verify completed by 08:00:27Z.

## Timeline (key events, UTC)

| Time | Event | Evidence |
|---|---|---|
| 07:49:58 | WINWORD entry (manual open) | E1 es_id `AaD7l6iPmO7CP6Oa3wXX` |
| 07:49:59 | macro self-write of config/HTA/beacon | `c0015wf.log` |
| 07:50:00 | mshta → regsvr32 → beacon powershell | E1 chain (parent joins verified) |
| 07:50:03 | phase3 register | C2-SIM `S1-0d84eba20418da28` |
| 07:50:28–48 | discovery + share enumeration | E1 cmd/net view |
| 07:51:48 | LSASS surrogate E10 0x1010 | E1 → E10 |
| 07:52:56 | WMI pivot: rundll32 (par=WmiPrvSE, LabEntry) | E1 + E7 (ART-06-01 hash) |
| 07:53:00 / 07:53:02 | receipt ART-07-01-0e9f226e + second-session egress | server-side + E3 |
| 07:56:06 | **it.admin interactive logon (LogonType 10, fs01)** | 4624 event `AaD7naiPmO7CP6Mq9rLB` (logonid 0x35a46e2) |
| 07:56:38 | R19 alerts on the T10 logon | alert ids `af223b2f…`/`78029000…` |
| 07:58:09 / 07:58:11 | rclone round 1 → sink :9001 | E1 + E3; receipt 11/11 |
| 07:58:13 | rclone round 2 (E1 id AaD7n6iPmO7CP6QZBbpW) | receipt 11/11 (sink_files observed per round) |
| 07:59:05–38 | AnyDesk drop (Videos\) + run; ProcessHacker drop (C:\) | E11 + E1 |
| 08:00:27 | impact: note writes; 15 file names changed (creates observed as E11) | E11; Verify 30 bidirectional mismatches → Rollback → hash-equal |

## Detection results (run window)

Raw stored counts (upper bounds; suppression applies at execution): R16=273 (admin-share
access; no suppression configured), R06=257 (suppressed loop), R14b=140 (BB), R10=36,
R14a=32, R12=30, R04=9, R09=9, R11=9, R18=9, R13=8, R07=6, R08=6, R05=3, R17=3,
R20=3, R01=2, R02=2, R03=2, R15=2, **R19=2 (true positive — Type-10 it.admin logon)**.

At run time the suite had 21 rules (R01-R20); R21 had been retired before this run.

## Stage status and limitations

- All stages PASS (S6 is **NOT RUN** - orchestration stage, skipped) except **S12 (RDP) PARTIAL**: an interactive it.admin logon
  (4624 T10) was observed at 07:56:38Z giving R19 its positive match, but session
  lifetime/state after client close was not captured, so the stage is not claimed
  as fully characterized.
- S11 evidence = rclone E1/E3 + receipts with observed sink_files (no rclone-specific
  detection rule).
- Alert volumes are raw stored counts; dedup is enforced by rule-execution suppression.

## Verification

`python scripts/verify/verify_final_phases.py RUN-20261002-06` → **ACCEPTED**
(required events with parent/entity joins, canonical receipt hashes, artifact_index
hash equality, manifest_hash equality).

## References

- Ledger + artifacts: `evidence/runs/RUN-20261002-06/`
- Rule index: `detections/README.md`


## Alert volume breakdown (RUN-20261002-06 window, stored alert docs)

| Rule | Alert docs | Suppressed matches (docs_count) | Unique groups | Unique entities | Note |
|---|---|---|---|---|---|
| R16 Admin Share Access | 273 | 0 (supp not yet configured in-window) | — | — | suppression host+SubjectLogonId+ShareName 5m added 2026-10-02 after this window |
| R06 Script Host Egress | 258 | 0 | — | 13 | entity suppression in place; the 13 entities are the real activity count |
| R14b Elevated Privileges | 158 | 0 (supp not yet configured in-window) | — | — | suppression host+SubjectLogonId 5m added after this window |
| R17 WMI pivot (alerting) | 3 | 0 | 1 | 1 | three docs = one activity (sweep duplication) |
| R18 Proxy egress (alerting) | 9 | 0 | 3 | 3 | three distinct activities |

Interpretation: stored alert docs are NOT analyst investigations. After the suppression
tuning, R16/R14b are expected to collapse to per-logon/per-session groups and R17/R18 to
their unique sequence counts. kibana.alert.suppression.docs_count was 0 for this window
because the suppression fields were configured after it; re-measure on the next run.


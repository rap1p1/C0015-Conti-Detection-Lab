# Reference Run Report — RUN-20261002-05 (final campaign, C0015)

Window: 2026-10-02 05:41:00Z – 06:12:00Z. Ledger: `evidence/runs/RUN-20261002-05/`.

## Summary

The lab replayed the C0015 intrusion end to end under one run id: macro self-write
entry (S1) → discovery and credential access from the beachhead (S4–S7b) → SMB handoff
and WMI pivot (S8a/S8b) → second session with server-side receipt (S9) → collection
(S10) → two rclone transfer rounds to the internal sink (S11a/b with RDP between) →
remote-tool deployment (S13) → bounded impact with verified rollback (S14).

## Timeline (key events, UTC)

| Time | Event | Evidence |
|---|---|---|
| 05:41:41 | WINWORD entry (manual open) | E1 es_id `AaD7IqiPmO7CP6IDoEJi` |
| 05:41:42 | macro self-write of config/HTA/beacon | `c0015wf.log` |
| 05:41:43 | mshta → regsvr32 → beacon powershell | E1 chain |
| 05:41:44 | phase3 register | C2-SIM `S1-9a7cab91e7fd4f9f` |
| 05:42:06–39 | discovery + share enumeration | E1 cmd/net view |
| 05:44:03 | LSASS surrogate E10 0x1010 | E1 → E10 |
| 05:44:49 | it.admin network logon (FS01) | 4624 T3 |
| 05:45:11 | WMI pivot: rundll32 (par=WmiPrvSE) | E1 + E7 (ART-06-01 hash) |
| 05:45:12 | receipt ART-07-01-18c677ef | server-side |
| 05:48–51 | collection staging (11 files) + zips | E11 + S5145 (381; C$:377) |
| 05:58:35 / 06:01:29 | rclone rounds 1 + 2 → sink :9001 | E1 rclone, E3, receipts 11/11 hash each |
| 05:46–06:01 | RDP session observed (Conn); network logons (4624 T3); no T10 | 4624 + query session |
| 06:02:21–55 | AnyDesk drop (Videos\) + run; ProcessHacker drop (C:\) | E11 + E1 |
| 06:04:06–07 | impact: corpus + note writes | E11; Run 15 files; Rollback hash-equal |

## Detection results

At run time the suite had 22 rules (R01–R21); R21 was retired after the run, so the current suite is 21 rules (R01–R20). Alerting rules: R17 (WMI pivot), R18 (proxy-spawned
egress). Raw stored counts for the window (uppercase bounds; suppression applies at
execution): R16=340 (no suppression configured), R14b=288 (BB), R10=78, R14a=72,
R12=33, R11=9, R18=9, R13=8, R17=3, R15=2, R20=3. R19 produced no match (no
completed Type-10 RDP logon in the window). R21 was retired after this run.

Building-block consumption: R17 correlates with R14a/R14b/R16 and the earlier
discovery rules; R18 correlates with R05/R09/R10/R11/R04 (see the correlation map in
`detections/README.md`).

## Partial stages and limitations

- **S12 (RDP) — PARTIAL**: network logons (4624 T3) and a session in `Conn` state were
  observed; a fully interactive (Type 10) logon was not completed in the lab, so R19
  lacks a positive test for this run.
- **S14 impact** is a bounded, allowlist-capped, reversible surrogate; the corpus/backup
  comparison at run time was one-directional (corpus vs backup); the surrogate code has since been hardened to a bidirectional comparison - the running verification for future runs must come from a new run.
- **S11**: no rclone-specific detection rule exists; the transfer is evidenced by the
  rclone E1/E3 and the ART-09-01 receipts (hash equality vs ART-08-01 manifest).
- Alert volumes are raw stored counts; dedup is enforced by the suppression groups at
  rule execution and should be re-measured rather than assumed.

## References

- Ledger + artifacts: `evidence/runs/RUN-20261002-05/`
- Rule index + mapping: `detections/README.md`
- Verify tooling: `scripts/verify/verify_final_phases.py`
- Detection-run notes: `phases/phase3-final-campaign/detection-run-20261002-05.md`


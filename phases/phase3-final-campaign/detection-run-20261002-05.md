# Detection Run RUN-20261002-05 (Final E2E Campaign)

Window: 2026-10-02 05:41:00Z -> 06:12:00Z (entry chain at 05:41:41Z, impact at 06:04Z).

## Campaign result
- S1-S15 completed under one run_id: macro self-write entry (3rd consecutive reproducible
  entry), remote operator on WS01, WMI pivot to FS01, collection (11 files), real-rclone
  transfer in two rounds to the local WebDAV sink (11/11 hash match per round), RDP
  network-auth on FS01, AnyDesk + ProcessHacker drops (Videos\ and C:\), bounded impact
  (15 files, verified + rolled back to hash-equal state).
- Receipts/artifacts: ART-07-01-18c677ef, ART-08-01, ART-09-01 (rounds 1+2),
  ART-14-01, ART-15-01 - indexed in the run ledger.

## Alert coverage (raw counts in/after the window; sweep incl. duplicates)
R16=340 (S5145 admin-share writes; add suppression group_by ShareName+RelativeTargetName
in a follow-up), R14b=288 (BB), R10=78, R14a=72, R12=33, R11=9, R18=9, R13=8, R17=3,
R15=2, R20=3 (AnyDesk drop+run; validated via AnyDesk2 re-validation), R21=3 (impact
README notes), R19=0 (gated on completed type-10 logon; RDP logged as T3/T4 network-auth).

## Quality notes (for follow-up)
1. R16 suppression key missing -> 340 raw alerts from ~377 S5145 C$ events; add
   alert_suppression group_by (host.name, winlog.event_data.ShareName,
   winlog.event_data.RelativeTargetName) 5m.
2. R19 needs a complete type-10 RDP logon for an end-to-end validation (lab closed the
   session at Conn; observed 4624 T3/T4 network-auth only).
3. R20/R21 were validated on-run after the generator query-loader bug was fixed
   (rules imported with an empty query - "query is null or empty" - fixed in
   gen_rules_ndjson.ps1).
4. FS01 phase7-session2 beacon died once mid-run and was respawned via WMI (direct
   powershell beacon); noted in the ledger.
5. Legacy R12-R18 rule notes are Vietnamese - translation to English is tracked debt
   (repo language policy: English).

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
R15=2, R20=3 (portable-tool drop/run), R21=3 (impact
README notes), R19=0 (no interactive T10 logon; RDP logged as T3/T4 network-auth).

## Operational notes
1. R16 emits ~340 alerts from ~377 S5145 C$ events; suppression (host, ShareName, RelativeTargetName) should be added when the volume is not acceptable.
   alert_suppression group_by (host.name, winlog.event_data.ShareName,
   winlog.event_data.RelativeTargetName) 5m.
2. R19 reports only after a fully interactive (T10) logon; the reference run closed the
   session at Conn, so only T3/T4 network-auth was observed.
3. R20 and R21 matched during the run. Note for rule maintenance: the generator loads
   every rule file through its loader list; a rule missing from that list imports with an empty query and fails at execution ('query is null or empty') - see
   gen_rules_ndjson.ps1).
4. The FS01 second-session beacon was respawned once via WMI (direct
   powershell beacon) during the run; recorded in the ledger.
5. R12-R18 rule metadata notes predate the repository language policy and are -
   


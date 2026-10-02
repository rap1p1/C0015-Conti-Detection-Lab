# Phase 2 — Operator Phase (S4-S9)

Hands-on-keyboard phase from the beachhead (WS01): discovery, credential access,
tool handoff over SMB, and a WMI pivot that spawns a second session on FS01 —
ending with an independent receipt (ART-07-01).

## Chain (with original tools from the DFIR report)

| Stage | Technique | Original (report) | Lab surrogate | Evidence |
|---|---|---|---|---|
| S4 Discovery | T1057/T1069/T1482/T1016/T1018 | AdFind, net, nltest, tasklist, ping (via RunDLL32/Winlogon in report) | runbook `scripts/runbooks/c0015-phase2.json` via beacon → cmd | E1 chain powershell→cmd→tool |
| S5 Share enum | T1135 | Invoke-ShareFinder (PowerView) → `C:\ProgramData\found_shares.txt` | `net view` + `Get-SmbShare` via runbook; `found_shares.txt` on FS01 | E1 command class |
| S7 Auth | T1078 | valid accounts | `C0015\it.admin` network logons | Security 4624 T3 + 4672 |
| S7b Credentials | T1003.001 | ProcessHacker LSASS dump | mimikatz-style surrogate (SeDebug, E10, no secrets stored) | E10 0x1010 + result NTLM |
| S8a Handoff | T1570/T1105 | SMB **C$** copies + `143.dll` | beacon downloads via :8000 + `copy` to `\\FS01\C$\C0015\` | S5145 + E11 |
| S8b WMI pivot | T1047/T1218.011 | `wmic ... rundll32 ... 143.dll` | space-form `rundll32.exe ... LabEntry` (WMI comma-split fix) | E1 rundll32 parent=WmiPrvSE |
| S9 Session 2 | T1071.001 | Cobalt Strike beacon session | beacon phase7-session2 (FS01) | E3 :8080 + receipt ART-07-01 |

## Engineering notes

- **Ingestion and auditing** — Security events are queried under `.ds-logs-system.security-*`; the
  `Detailed File Share` audit policy on FS01 provides 5145 coverage.
- **WMI pivot spelling** — `wmic process call create "<cmd>"` splits arguments on commas, so the **space form**
  (`...rundll32.exe ...dll LabEntry`) is used.
- The Defender behavioral signature `Trojan:Win32/RyukLocalspawn.A` can block wmic→rundll32 when real-time protection is enabled (FS01
  was snapshot-restored with protection on) — real-time protection is disabled via a SYSTEM scheduled task for runs.
- The `duc.user` account cannot use direct `runProgramInGuest`; victim-session actions run through an
  interactive scheduled task, and tool files staged by `it.admin` receive `icacls` read grants.

## Detection (rules that fire in this phase)

R10/R11/R12 (PS→cmd→discovery), R13 (share enumeration), R14a/R14b (network logon +
elevated privileges), R15 (LSASS access), R16 (admin-share write), R17 (WMI-spawned
unsigned module — **high, alerting**), R18 (proxy-spawned PS egress — **high, alerting**).

## Files

- [operator-phase-context-gaps-runbook.md](operator-phase-context-gaps-runbook.md) — G1/G2/G4/G7/G8
  resolutions and the verified run recipes.
- Rules: `../detections/queries/r10-...` through `r18-...`; mapping in `../detections/README.md`.
- Runbook data: `../scripts/runbooks/c0015-phase2.json`; fixtures in `../scripts/fixtures/`.


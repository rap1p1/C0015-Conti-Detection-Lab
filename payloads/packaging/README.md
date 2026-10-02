# payloads/packaging — build / install / preflight / orchestrator

Harness tooling that produces the runnable artifacts and drives the campaign.

| Script | Purpose |
|---|---|
| `run_campaign_orchestrator.ps1` | `-Action Pre\|P1\|P2\|P3\|Artifacts\|Stop` — per-run config, server side, staged files, receipts guide, cleanup |
| `make_config.ps1` | generates per-run `config.ini` + `config-phase7.ini` (no secrets; token generated at runtime) |
| `gen_macro_embedded.ps1` | builds `stage/ws01/macro_embedded.vba` (self-contained standard-module macro with base64 blobs) |
| `install_macro_docm.ps1` | injects the VBA into a `.docm` — `$doc.VBProject` + standard module `c0015Payload`, `AutoOpen` trigger, entry-macro guard |
| `launch_servers.ps1` | starts/stops C2-SIM (guard-aware) + HTTP staging server (`-Stop` stops both) |
| `preflight_vmrun.ps1` / `preflight_win.ps1` / `preflight_kali.sh` | machine readiness checks (hostname trim, tools, Escalate bash) |
| `defender_off.ps1` | disables Defender via a SYSTEM scheduled task (used after snapshot reverts) |

## Key techniques

- **Document-project injection** (`install_macro_docm.ps1`): `$doc.VBProject` (not
  `$word.VBE.ActiveVBProject`, which resolves to Normal.dotm and silently saves a
  macro-less docm); standard module instead of `ThisDocument` (inherited-member
  collisions); only `AutoOpen` as the trigger; guard requires exactly one entry macro.
- **Macro self-write chain** (`gen_macro_embedded.ps1`): every staged file is embedded
  as base64 chunks, joined at runtime (Const-concatenation is fragile), decoded and
  written with native VBA I/O (`Open For Binary` + `Put`), step-logged to
  `C:\Windows\Temp\c0015wf.log`.
- **Orchestrator Pre** regenerates configs with the run id, seeds nothing on the victim
  disk (the macro writes everything), and starts the servers (watchdog-aware; the
  `launch_servers.ps1 -Stop` path stops watchdog + C2-SIM + HTTP together).
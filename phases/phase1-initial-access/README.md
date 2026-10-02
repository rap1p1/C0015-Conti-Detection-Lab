# Phase 1 — Initial Access Chain (S1-S3)

The entry phase: a weaponized Word document whose **macro self-writes** the full staged
toolchain to disk (config.ini, bootstrap.hta, c0015_beacon.ps1), then hands off to
mshta → HTA → regsvr32-loading DLL surrogate → beacon.

## Chain (with original tools from the DFIR report)

| Step | Technique | Original (report) | Lab surrogate | Evidence |
|---|---|---|---|---|
| Delivery/exec | T1566.001 → T1204.002 | password-protected zip + macro Word doc | manual victim open of `c0015_entry.docm` (AutoOpen macro) | E1 WINWORD (par=explorer) |
| Macro self-write | T1059.005 + T1105 | macro drops HTA (files) | macro **writes config/hta/beacon natively** (no COM) | `c0015wf.log` step log + E11 by WINWORD |
| HTA bootstrap | T1218.005 / T1059.007 | encoded HTA + JS/VBScript | `payloads/hta/bootstrap.hta` (config-driven) | E1 mshta (par=WINWORD) |
| DLL surrogate | T1218.010 / T1105 | `compareForfor.jpg` → regsvr32 | `c0015-comparefor.jpg` → regsvr32 /s | E7 jpg-as-DLL + E11 |
| Beacon | T1071.001 | BazarLoader → Cobalt Strike | `c0015_beacon.ps1` (phase3) → C2-SIM :8080 | `register` on C2-SIM |

## Self-generating entry macro

Before the victim opens the document, the WS01 disk holds **no lab tooling** — the
macro creates it at runtime. Production recipe (see the design doc in this folder):

1. `payloads/packaging/gen_macro_embedded.ps1` — builds a self-contained standard-module
   VBA source with the config/HTA/beacon embedded as base64 chunks, joined at runtime
   (no Const-concatenation), native-I/O decoder/writer, single `AutoOpen` trigger.
2. `payloads/packaging/install_macro_docm.ps1` — injects the module into **the document's
   own VB project** (`$doc.VBProject`) as a **standard module** (`c0015Payload`), never
   into `ThisDocument` (avoids inherited-member collisions) and never via
   `Word.VBE.ActiveVBProject` (which resolves to `Normal.dotm` and silently saves a
   macro-less .docm).
3. Open requirements: interactive Word session + auto-macros enabled + a clean Word
   state (Word's `Resiliency\DocumentRecovery` must be cleared after any crash/kill —
   recovered documents do not run Document_Open/AutoOpen).

## Detection (rules that fire in this phase)

R01 (office→script/shell), R02 (mshta→regsvr32/rundll32), R03 (E7 unsigned staging),
R04 (staging file writes — catches the macro self-write), R05 (regsvr32→PS),
R06 (script-host egress), R07 (office→mshta→proxy sequence), R08 (unsigned module→PS).

## Files

- [initial-access-chain-design.md](initial-access-chain-design.md) — entry-chain design,
  macro self-write investigation records, operator-phase design.
- Payloads: `../payloads/docm/`, `../payloads/hta/`, `../payloads/dll/`, `../payloads/beacon/`,
  `../payloads/packaging/`.
- Chain context: `../docs/attack-chain-plan.md` (S1-S3 rows), `../docs/attack-runbook.md`.



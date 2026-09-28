# Detections

Detection rules for the C0015 Conti Detection Lab, organized by type and phase.

## Directory Structure

- `atomic/` — Low-confidence KQL building blocks. Each rule targets a single behavior family and is
  intentionally broad to preserve recall (no notification actions; reusable signals).
- `eql/` — Entity-aware EQL sequence prototypes that enforce parent-child ordering via ProcessGuid
  ancestry (`process.entity_id` ↔ `process.parent.entity_id`), same-host only. Telemetry validation
  and chain-level detection.
- `correlations/` — (planned) Analyst-facing ES|QL chain alerts over the atomic/EQL signals.

## Phase scope

The current rule set covers **phase 1 — entry → bootstrap → session 1** (stage S1–S3; S4 boundary stays
`PARTIAL`). All rules are grounded on the verified `RUN-20261001-01` telemetry in Elastic
(`logs-windows.sysmon_operational-c0015-*`, host `ws01`, 2026-09-28T02:15Z).

The previous C1-era discovery/collection content was removed: it belongs to the operator/discovery phase
(phase 2) and will be re-baselined against phase-2 telemetry when that phase runs.

## Phase-1 rules

Status: `NOT RUN` (drafts, not enabled) — TP verified on the run above; **validation gate pending**
(control + variation runs required before any rule is called `validated` / `DETECTED`).

| Layer | File | Behavior (no IOC hardcode) | Verified TP (record_id, WS01) |
|---|---|---|---|
| Atomic | `atomic/phase1-office-spawns-script-shell.kql` | Office parent → {cmd, mshta, powershell, wscript, cscript, regsvr32, rundll32} | 217060 |
| Atomic | `atomic/phase1-mshta-proxy-load.kql` | mshta/wscript/cscript → {regsvr32, rundll32} | 217082 |
| Atomic | `atomic/phase1-unsigned-userwrite-load.kql` | E7 image from Public/Temp/ProgramData + `winlog.event_data.Signed:"false"` | 217090 |
| Atomic | `atomic/phase1-public-staging-drop.kql` | E11 `C:\Users\Public\*` by script/proxy process | 217079/217080/217096/217086 |
| Atomic | `atomic/phase1-nested-cmd-under-powershell.kql` | PS → cmd double-wrapped `cmd /c "cmd.exe /c …"` | 217129/217218/217240 |
| Atomic | `atomic/phase1-c2-callback-lab.kql` | E3 → lab dest port 8000/8080 (lab-boundary) | 217143; ×7 :8080 |
| EQL | `eql/phase1-bootstrap-chain.eql` | WINWORD → mshta → regsvr32, ProcessGuid ancestry, maxspan 2m | 217026→217060→217082 |
| EQL | `eql/phase1-beacon-task-execution.eql` | PS → outer cmd (nested) → inner cmd → {net, tasklist, nltest, whoami, wmic}, maxspan 30s | 217129→217134→217135 |

## Design rules (derived from verified telemetry)

- **No IOC hardcoding**: no filenames (`c0015-comparefor.jpg`, `bootstrap.hta`), no DLL sha256, no
  `C:\Users\Public\C0015` folder inside conditions — path class + signature class + behavior only;
  hashes/IPs are enrichment fields.
- E7 signature check uses `winlog.event_data.Signed` — `file.code_signature.signed` is **not populated**
  on this integration (verified).
- E3: `network.protocol`/`Initiated` are not populated (verified) — do not filter on them; E3 timestamps
  lag ~2–3 s vs E1/E11 in the same stream, so never order the chain by E3 time.
- EQL joins by `host.id` only (ProcessGuid is host-local, never cross-host); use `like` for casing
  robustness (`WINWORD.EXE` is uppercase on disk — verified).
- RecordID alone is ambiguous (Sysmon channel reset between 2026-09-19 and 2026-09-28 reused values) —
  rules rely on time windows and ancestry, never on RecordID alone.

## Validation gate

`validated` only when: target run (done, see `stage/analysis/s1-s4-detection-report.md`) + **control**
baseline (no-document run: atomics ≈ 0, EQL 0) + **≥1 variation** (missing hop, signed DLL in Public,
task without discovery child) + reproducible from query + dataset.

## Transition note

- Removed this commit: the C1-era discovery/SMB-collection atomics, cmd-sequence EQL prototypes, and
  `correlations/discovery-to-smb-collection.esql` (phase-2 scope).
  `docs/correlation-architecture.md` §C1 still references that correlation — stale until phase-2 rules land.
- Next step: correlation layer (chain alert over phase-1 atomics + EQL, single-host, 10-minute window)
  once the EQL rules are enabled and rule names are frozen (avoids C1's rule-name dependency issue).
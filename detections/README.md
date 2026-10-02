# Detections

Detection rules for the C0015 Conti Detection Lab, organized by type and phase.

## Directory structure

- `eql/` — the phase-1 rule set (11 rules, all Elastic EQL). Single-event predicates and
  ProcessGuid-ancestry sequences. Import-ready for Elastic Security (rule type **EQL / Event correlation**,
  index `logs-windows.sysmon_operational-c0015*`).
- `atomic/` — removed in the review: unified into the single-event EQL rules below (R01–R06, R10, R11).
- `correlations/` — (planned) analyst-facing ES|QL chain alert on top of these signals.

## Phase scope

Phase 1 — entry → bootstrap → session 1 (S1–S3) plus the S4 boundary (R10/R11 task-loop). Grounded on
`RUN-20261001-01` Discover export (WS01, `C0015\duc.user`, 2026-09-28T02:13–02:17Z) and cross-checked against
the rerun alert exports: pre-filter 46 docs (33 low / 4 medium / 9 high), **post-filter rerun (Alerts (1).csv)
40 docs (27 low / 4 medium / 9 high)** — R04 dropped 14→8 with the PowerShell `__PSScriptPolicyTest_*` exclusion
active; all other rules unchanged.

## Post-filter validation notes (2026-09-28 rerun, cross-checked on raw Sysmon)

| Item | Cross-check result |
|---|---|
| R01/R02/R03/R05 = 1 each | One true positive per rule (WINWORD→mshta `235024`; mshta→regsvr32 `235041`; E7 unsigned `235045`; regsvr32→PS `235048`). |
| R04 = 8 | 4 staging writes (folder `C:\Users\Public\C0015` + config.ini/bootstrap.hta/c0015_beacon.ps1) + 4 chain artifacts (b64-marker, c0015-comparefor.jpg, dll-executed.txt, js-marker). The `file.name=C0015` row is the **staging folder create** (E11 TargetFilename = directory, producer = staging powershell) — expected staging evidence. |
| R06 = 7 | Exactly the 7 beacon E3 egress to `192.168.50.1:8080` (register + 3 task/next + 3 result). **No mshta→`:8000` E3 exists in the rerun raw telemetry** even though the download-proving file write occurred — R06 is correct; this is a per-run E3 gap for mshta (record, don't treat as rule miss). |
| R07/R08/R09/R11 = 3 docs each | One real sequence per rule (all 3 docs share one alert timestamp: the sequence's constituent events). Do not read "3" as three sequences. |
| R10 = 9 | Three real nested-CMD sequences (`net view /all` + 2× `cmd /c ver` fallbacks) re-matched by two consecutive 1-min schedule ticks (alert timestamps 60 s apart) → **scheduled-rule duplication**. Enable alert suppression (by host/process GUID) or dedupe on `kibana.alert.uuid` at analysis. |

These are reference counts on one rerun; `validated` still requires control/variation runs. For clean
re-correlation, scope source queries to `winlog.channel : "Microsoft-Windows-Sysmon/Operational"` (alert docs
in `.internal.alerts-security.*` copy the source event's `record_id`/`entity_id` but carry alert-time
`@timestamp`).

## Rules (R01–R11)

All rules: tag `C0015`, MITRE ATT&CK v18, no actions. Imported **disabled** (preview); **enabled for the
2026-09-28 post-filter rerun** — the deployed state is captured in the committed export
`eql/C0015-S1-S3-elastic-rules.ndjson` (11 rules, includes the R04 policy-test exclusion).
**Building block ON** hides the alert from the default Alerts table (R01–R06, R10, R11);
**building block OFF** rules are the alerting correlations (R07–R09).

| ID | File | Scope | Sev/risk | BBlock | Candidate (run export) | Alerts.csv (rerun) |
|---|---|---|---|---|---|---|
| R01 | `eql/r01-office-spawns-script-host-shell.eql` | S1: Office → script/shell/proxy | medium / 47 | ON | `217060` | 1 |
| R02 | `eql/r02-script-host-spawning-proxy-loader.eql` | S2: mshta/wscript/cscript → regsvr32/rundll32 | medium / 47 | ON | `217082` | 1 |
| R03 | `eql/r03-proxy-loader-loading-unsigned-module.eql` | S2: E7 unsigned module from staging path | medium / 47 | ON | `217090` | 1 |
| R04 | `eql/r04-script-or-proxy-staging-file-write.eql` | S2–S3: E11 staging-path write (PowerShell policy-test excluded) | low / 21 | ON | chain: 217079/217080/217086/217096 | 8 (post-filter) |
| R05 | `eql/r05-proxy-loader-spawning-powershell.eql` | S3: regsvr32/rundll32 → PowerShell | medium / 47 | ON | `217088` | 1 |
| R06 | `eql/r06-script-host-network-egress.eql` | S2–S3: E3 egress by script processes (no IP/port hardcode) | low / 21 | ON | mshta `:8000` + 7 PS `:8080` | 7 (all PS → `192.168.50.1`) |
| R07 | `eql/r07-office-to-mshta-to-proxy-loader.eql` | S1–S2 sequence: Office→mshta→proxy loader (GUID join) | high / 73 | OFF | `[217060, 217082]` | 3 |
| R08 | `eql/r08-unsigned-module-load-to-powershell.eql` | S2–S3 sequence: unsigned load → PowerShell child | high / 73 | OFF | `[217090, 217088]` | 3 |
| R09 | `eql/r09-proxy-spawned-powershell-network-egress.eql` | S3 sequence: proxy-spawned PS → E3 egress | high / 73 | OFF | 7 candidates (E1 `217088` × E3) | 3 |
| R10 | `eql/r10-powershell-spawning-nested-cmd.eql` | S3 task-loop / S4 boundary: PS → nested CMD | low / 21 | ON | 3 (`net view` + 2× `cmd /c ver`) | 9 |
| R11 | `eql/r11-nested-cmd-launching-discovery-tool.eql` | S4 boundary (optional): nested CMD → discovery-capable tool | low / 21 | ON | `[217134, 217135]` (`net view /all`) | 3 |

Notes:
- CSV counts are **alert documents on the rerun**, not incidents. R07/R08/R09 show 3 docs each → verify
  `kibana.alert.uuid`/sequence ancestors before calling them 3 sequences (building blocks OFF = correlation
  alerting could aggregate constituent events). R10 has 9 docs around two time clusters (~1 min apart) —
  check whether that is a second task round or scheduled-run duplication.
- R06 in the rerun CSV shows 7 PowerShell egress to `192.168.50.1` and **no mshta `:8000` row** — unresolved
  (rerun had no such event vs query/time window vs export); cross-check raw E3 before concluding.
- R11 fires on `net.exe` — in this run the command line was `net view /all` (T1135). `cmd /c ver` fallbacks
  (T-NOOP) are **not** discovery; R10 catches them, R11 does not.

## R04 policy-test exclusion

`r04-script-or-proxy-staging-file-write.eql` is committed and evaluated with PowerShell's built-in
`__PSScriptPolicyTest_*` policy-test temp files excluded:

```eql
  and not (process.name : ("powershell.exe", "pwsh.exe") and file.name : "__PSScriptPolicyTest_*")
```

Rule counts in this repo are presented post-filter (R04 matches the chain artifacts 217079/217080/217086/217096).

## Validation status

- `OFFLINE_CHECKED_ELASTIC_PREVIEW_PENDING` — predicates and ProcessGuid joins checked offline on the run export
  (6 synthetic tilt cases passed: case change, broken parent GUID, signed module, bad E3 PS GUID, different host,
  IP/port change). **Not** an Elastic EQL parser test and **not** a VM control/variation validation.
- Next steps before enabling any rule: Kibana rule preview on `logs-windows.sysmon_operational-c0015*` (window
  02:13–02:17Z / 09:13–09:17 UTC+7), then baseline/control benign run + variation, then `DETECTED`.
- Do not treat candidate counts in `note` fields as alert counts.

## Design rules (from verified telemetry)

- No IOC hardcoding: no filenames, DLL sha256, `C:\Users\Public\C0015`, or lab IP/port in rule conditions.
  Process/path **classes**, signature class, egress behavior, and ProcessGuid ancestry only.
- E3 uses `network.direction == "egress"` + non-empty `process.entity_id` (ProcessGuid). `network.protocol`,
  `Initiated`, and `file.code_signature.signed` are **not populated** on this integration — do not use them.
  E3 timestamps lag ~2–3 s vs E1/E11 in the same stream (never order the chain by E3 time).
- E7 signature check uses `winlog.event_data.Signed` (string `"false"`); `Signed=false` alone does **not**
  warrant T1553.002.
- EQL sequences join `by host.id` with `process.entity_id` ↔ `process.parent.entity_id` (ProcessGuid), never
  PID and never cross-host. `:`/`like` operators for case-insensitive names (`WINWORD.EXE` is uppercase).
- RecordID alone is ambiguous (Sysmon channel reset reused values 2026-09-19 vs 09-28) — always window-bound.
- No rule asserts C2 registration/task success from E3 alone; the server-side `c2sim.log` receipt is the
  independent confirmation source.

## Sources

- Elastic rules: committed export `eql/C0015-S1-S3-elastic-rules.ndjson` — 11 rules, **post-filter, enabled**
  (the state that produced the 40-alert rerun; R04 includes the `__PSScriptPolicyTest_*` exclusion). The
  pre-filter review export (disabled) lives with the review handoff, not in this repo.
- Rerun alerts: `Alerts (1).csv` (40 docs; summary fields only — open in Kibana for uuid/RecordID/command line).
- Review handoff: `HANDOFF-C0015-S1-S3.vi.md`; full phase-1 analysis: `../stage/analysis/s1-s4-detection-report.md`.

## Operator-phase rules (R12–R18) — S4–S9

Import file: `eql/C0015-S4-S9-elastic-rules.ndjson` (8 rules, **enabled**, interval 1m, from now-6m).
Grounded on `RUN-20261002-01` (verified telemetry) + validation run `RUN-20261002-02` (coverage/noise report
trong `../docs/detection-run-20261002-02.md`). Rules không hardcode giá trị lab (không IP/host/port/hash/account;
chỉ process/path **class**, signature class, command-line class và entity ancestry).

| ID | File | Scope | Sev/risk | BBlock | Preview (RUN-…-01) | Rerun-…-02 alerts | Ghi chú |
|---|---|---|---|---|---|---|---|
| R12 | `eql/r12-powershell-nested-cmd-launching-discovery.eql` | S4: PS→cmd→discovery tool | low / 21 | ON | 3 | 30–72 (sweep dup) | entity chain 2 bước |
| R13 | `eql/r13-share-enumeration-commands.eql` | S5: net view/use + Get-SmbShare | low / 21 | ON | 3 | 17 (dup) | command-line class |
| R14a | `eql/r14a-network-logon-by-user.eql` | S7: 4624 Type 3 non-system user | low / 21 | ON | 4 | 27 (dup) | Security `logs-system.security-c0015*` |
| R14b | `eql/r14b-elevated-privileges-assigned-to-user.eql` | S7: 4672 non-system user | medium / 47 | ON (sau tuning) | 4 | 139 (noise → BB ON) | beacon elevated logon lặp = FP |
| R15 | `eql/r15-lsass-credential-access.eql` | S7b: E10 lsass 0x1010/0x1418/0x1fffff non-system | medium / 47 | ON | 1 (wide 27.5h: 2, 0 FP) | 3 (1 TP + dup) | ambient system bị loại |
| R16 | `eql/r16-admin-share-remote-file-write.eql` | S8a: 5145 C$/ADMIN$ | low / 21 | ON | 0 (audit-gated) | 0 (audit-gated) | cần Detailed File Share audit |
| R17 | `eql/r17-wmiprvse-spawns-process-loading-unsigned-module.eql` | S8b: wmiprvse→child→E7 unsigned | high / 73 | OFF | 1 (wide: 3, 0 FP) | 9 (3 sweep × chain) | E7 dùng `[any where]` (category library) |
| R18 | `eql/r18-proxy-spawned-powershell-egress.eql` | S9: rundll32/regsvr32→PS→egress | high / 73 | OFF | 2 | 12 (dup) | E3 lag 2–3s so E1 |

Ghi chú thiết kế (rút từ telemetry verified):
- E7 có `event.category` = library → trongsequence phải dùng `[any where event.code=="7"]` — `process where` sẽ lọc mất.
- 4624: `winlog.logon.id` = 0x0 (SubjectLogonId) — không join được 4624↔4672 theo logon id; dùng 4672 single
  (R14b) + nối tay theo `TargetLogonId` khi điều tra.
- E11 SMB write phiá target không giữ UNC/Image/User → S8a chỉ dùng 5145 (R16) — audit-gated.
- Sweep duplication (interval 1m vs look-back 6m) làm cùng event match nhiều sweep — kiến nghị enable
  **alert suppression** (group_by `process.entity_id`/`host.name` + duration) hoặc dedupe theo uuid khi phân tích
  (đã thấy ở R10 từ phase-1).
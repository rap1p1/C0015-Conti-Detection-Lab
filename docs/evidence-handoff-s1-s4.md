# Evidence Handoff — Session 1 run (RUN-20261001-01)

Handoff bundle for the Detection Engineer session (Elastic analysis of the S1-S4
phase-1 run). Ground truth and machine evidence only — no interpretation is added
here beyond what is on the wire.

## Run identity

- run_id: RUN-20261001-01 (from config.ini on WS01)
- scenario_id: C0015-LAB-1
- Host: WS01 (192.168.50.20, Windows 10, joined c0015.lab)
- Account: C0015\duc.user
- C2: 192.168.50.1:8080 (C2-SIM v2); HTTP artifact server 192.168.50.1:8000
- Times (UTC): entry at 2026-09-28T02:15:08Z; beacon register 02:15:10Z;
  beacon network callback at 02:15:11Z-02:15:31Z; discovery tasks 02:15:10Z-02:15:30Z
- Local clock: Asia/Bangkok (+07). WS01 Sysmon TimeCreated is local; UtcTime and
  this document use UTC. Verify clock skew vs host/C2 before cross-host windowing.

## Telemetry captured (S1-S4) and where it lives

| Stage | Event IDs | RecordID anchors (WS01 Sysmon) | Artifacts (sha256) |
|---|---|---|---|
| S1 entry | E1 | 217026 WINWORD->test.docm; 217060 mshta->bootstrap.hta | test.docm (macro) |
| S2 bootstrap | E1,E3,E7,E11 | E11 217079 b64-marker; 217080 c0015-comparefor.jpg; E3 217143 mshta->:8000; E11 217096 js-marker | bootstrap.hta F76FBDA4...; config.ini 590D81...; b64-marker.txt F091FD97...; js-marker.txt F196A245... |
| S3 session 1 | E1,E3,E7,E11 | E1 217082 regsvr32; E7 217090 ImageLoad dll; E11 217086 dll-executed.txt; E1 217088 beacon spawn; E3 217151/217212/217232/217233/217249/217250 beacon->:8080 | c0015-comparefor.jpg CEF7879F...; dll-executed.txt AC8E9396...; c0015_beacon.ps1 3C594543... |
| S4 discovery (partial, corrected) | E1 | REAL: 217135/217134/217129 net view /all (T1135). FALLBACK, not discovery: 217218/217223/217240/217242 cmd /c ver (T-NOOP; tasklist / net group never ran) | - |

Raw artifacts: `evidence/run-ledger/RUN-20261001-01.json` (ledger) and the structured
WS01 export `C:\Users\Public\c0015-evidence-structured.json` (from
`payloads/packaging/collect_ws01_evidence.ps1`).

## Fields available for correlation (from Sysmon EventData)

| Event | Correlation fields present | Notes |
|---|---|---|
| E1 | ProcessGuid, ProcessId, Image, CommandLine, User, LogonGuid, LogonId, Hashes, IntegrityLevel, TerminalSessionId, ParentProcessGuid, ParentProcessId, ParentImage, UtcTime | Parent* present in raw event; the structured collector now emits them. Join same-host only; never join PID across hosts/runs. |
| E7 | ProcessGuid, ProcessId, Image, ImageLoaded, Hashes, Signed, Signature, SignatureStatus, UtcTime | ImageLoad of c0015-comparefor.jpg has signed=false. |
| E11 | ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime, User | Staging writes under C:\Users\Public\C0015\. |
| E3 | ProcessGuid, ProcessId, Image, User, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, Initiated, UtcTime | Destination 192.168.50.1:8000 (mshta) and :8080 (beacon). |

## Chains and keys

- ProcessGuid ancestry (same host): WINWORD `...3808` -> mshta `...3908` (PID 3532)
  -> regsvr32 `...3c08` (PID 968) -> beacon powershell `...3d08` (PID 288).
- LogonId/LogonGuid captured per E1; use for the 4624/4672 join on FS01 only later,
  never for WS01 4648 <-> FS01 4624.
- Naming: `process.entity_id` ~ ProcessGuid, `process.parent.entity_id` ~ ParentProcessGuid
  (verify the mapping in Elastic before asserting; ECS names are not assumed).

## What is NOT yet verified

- Elastic ingest of these events (accepted RawEvent vs Discover query not yet confirmed).
- The structured JSON with Parent fields requires re-running the collector with the
  current version (b9e30fc+/structured) on WS01; the earlier JSON stored truncated
  Message text only.
- E22 DNS, E10 ProcessAccess: not collected (IPs used; E10 out of scope for S1-S4).
- Full S4 batch: only 1 real discovery command ran (net view /all). T-DISCOVER-SYSTEM/-DOMAINGROUPS executed the
  `cmd /c ver` fallback (deployed config.ini maps only CORPUS/SLEEP/NOOP); the 5 remaining tasks were not issued.

## Handoff queries

### PowerShell (WS01) — pull the exact events
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -ErrorAction SilentlyContinue |
  Where-Object { $_.RecordId -in 217026,217060,217079,217080,217096,217082,217086,217088,217090,217143,217151,217135,217129 } |
  Format-List TimeCreated,RecordId,ProviderName,Message
```

### Elastic (verify ingest + mapping)
```kql
host.name : "ws01" and winlog.channel : "Microsoft-Windows-Sysmon/Operational" and
event.code : ("1" or "3" or "7" or "11") and
@timestamp >= "2026-09-28T02:14:25Z" and @timestamp <= "2026-09-28T02:16:00Z"
```
Then, for at least one E1, confirm `process.entity_id` and `process.parent.entity_id`
strings match the ProcessGuid values above; for the E3 confirm
`destination.ip : 192.168.50.1` and related port fields.

## Gaps / status

- S1-S3 VERIFIED (machine + server log); S4 PARTIAL (1 real discovery command: net view /all; other issued tasks
  fell back to T-NOOP `cmd /c ver` — see Addendum).
- ParentProcessGuid join requires the structured export (or the Elastic EventData).
- Clock: UTC asserted in this handoff; verify against host C2 log before timeline
  joins.

## Addendum — Detection-engineering verification (2026-09-28, DE session; Elastic live check)

All 25 anchor records are **PRESENT in Elastic** (data stream `.ds-logs-windows.sysmon_operational-c0015-2026.09.12-000001`,
namespace `c0015`, host `ws01`, provider Microsoft-Windows-Sysmon). Windows also confirms 26 candidate indices including
`logs-windows.windows_defender-c0015` and `logs-system.security-c0015`.

**ECS mapping (verified on live docs):**
- `process.entity_id` == Sysmon ProcessGuid (braces stripped) — 4/4 anchors exact
  (WINWORD `...3808`, mshta `...3908`, regsvr32 `...3c08`, powershell `...3d08`); `process.parent.entity_id` == ParentProcessGuid.
- E7 `217090`: `file.hash.sha256` = `CEF7879F239C7F3185C2C3FAE19D2D5D46C3497458F33FDC22677FA4F6FF2BEB` (MATCH),
  signature in **`winlog.event_data.Signed` = "false"** and `winlog.event_data.SignatureStatus` = "Unavailable";
  `file.code_signature.signed` is **not populated** on this integration.
- E3 `217143` (mshta `:8000`) and the 7 beacon `:8080` events (`217149/217151/217212/217232/217233/217249/217250`)
  carry `process.entity_id` **and** PID/Image -> attribution is DIRECT (no P1-B-style gap this run).

**Record-ID reuse (NEW correlation caveat):** the Sysmon channel was reset between 2026-09-19 and 2026-09-28;
the same `winlog.record_id` values (217090, 217131, 217129, 217135, 217143, 217149, 217151, 217212) also exist on
09-19 as background E10/E3 events. **Never anchor RecordID without the run @timestamp window** (and ProcessGuid for re-runs).

**E3 timestamp latency:** E3 UtcTime for short-lived connections lags ~2-3 s behind causally-dependent E1/E11 in the
same stream (e.g. E11 217080 02:15:10.090 precedes E3 217143 02:15:12.309). Do not order the intra-host chain by E3 time.

**Corrections to this doc:** (1) `217131` is Sysmon **E9** (RawAccessRead, `System`, `\Device\HarddiskVolume1`), NOT a
cmd->net event — remove from the S4 cmd->net list (real cmd->net = 217129/217134/217135). (2) S4 T-DISCOVER-SYSTEM /
T-DISCOVER-DOMAINGROUPS executed the `cmd /c ver` fallback (E1 217218/217223/217240/217242), not tasklist/net group,
because the deployed config.ini (stage/ws01/config.ini, sha256 590D812D...) defines no task map for them; only
T1135 (net view /all) really ran.

**AV-disabled observable:** Defender/Operational `5001` @ 2026-09-27T13:05:16Z and `1151` @ 2026-09-28T02:07:33Z
(pre-run) on ws01; `5010` not observed in a 14-day window. Label `[LAB CONFIG]`.

Full detection report (per-event verify table, ATT&CK mapping, 6 DH with KQL, correlation, gaps):
`stage/analysis/s1-s4-detection-report.md` (working-tree scratch, not committed).
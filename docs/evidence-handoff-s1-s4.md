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
| S4 discovery (partial) | E1 | 217135 net view /all; 217129/217131 cmd->net; 217218/217223/217240/217242 cmd /c ver (T-NOOP) | - |

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
- Full S4 batch: only 3 of 8 discovery tasks ran in this window.

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

- S1-S3 VERIFIED (machine + server log); S4 PARTIAL (3/8 tasks).
- ParentProcessGuid join requires the structured export (or the Elastic EventData).
- Clock: UTC asserted in this handoff; verify against host C2 log before timeline
  joins.
# Investigation Methodology

## Overview

This document defines how an analyst should reconstruct the C0015 intrusion chain from detection alerts and telemetry. The methodology follows the campaign lifecycle rather than examining individual ATT&CK techniques in isolation.

## Reconstruction Sequence

An analyst investigating a C0015-pattern intrusion should reconstruct the following chain:

```text
initial execution → foothold → discovery → target selection
  → authentication → WMI lateral movement → target process
  → second callback → collection → transfer
  → remote access → impact
```

Each transition point represents a pivot opportunity where the analyst must connect evidence across hosts, accounts, and time.

---

## Investigation Priorities

### Process Ancestry

Trace the full parent-child process chain from the initial execution through each campaign stage:

```text
document/script → bootstrap → DLL load → callback agent
  → discovery commands → WMI initiation
```

On the target host:

```text
wmiprvse.exe → target process → callback agent
  → collection → transfer
```

Process ancestry is the primary evidence for establishing causal relationships between campaign stages.

### Host Transitions

Track which host originated each action and which host received it:

```text
WS01 (origin) → FS01 (lateral target)
```

Key evidence:
- Source IP in WMI/RPC connections
- Source IP in SMB 5145 events
- Logon events with workstation name
- Network connections with destination addresses

### Account Provenance

For every authenticated action, establish:

- Which account was used
- How the account was authenticated (interactive, network, remote interactive, explicit credential)
- Whether the account had the required privileges
- Whether the account usage was expected for that identity

**Critical note:** Correlation proves same-user, multi-host activity. It does not automatically prove that the same person controlled the account across all hosts. Correlation does not equal causation.

### Logon Evidence

Map logon types to investigation meaning:

| Logon Type | Meaning | C0015 Relevance |
|---|---|---|
| Type 2 (Interactive) | Console logon | Operator access at workstation |
| Type 3 (Network) | SMB, WMI, RPC | Lateral movement, file access |
| Type 7 (Unlock) | Screen unlock | Session continuity |
| Type 10 (RemoteInteractive) | RDP | Secondary remote access |

Track logon events (4624), failed logons (4625), explicit credential use, and privileged logon (4672) across all hosts.

### File and Share Access

For collection and impact stages, correlate:

- Which shares were accessed (5145 events on FS01)
- Which files were read, written, or modified
- Which account performed the access
- Source IP of the accessing system
- Timing relative to discovery and lateral-movement activity

### Network Relationships

Map network connections between hosts during each campaign stage:

- WMI/RPC from WS01 to FS01
- Callback connections from both WS01 and FS01
- SMB file access patterns
- RDP sessions
- Transfer connections to exfiltration destination

### Timestamps

Establish a timeline across all hosts with attention to:

- Time synchronization between endpoints and the domain controller
- Sequence of events across the intrusion chain
- Gaps in the timeline that may indicate unobserved activity
- Temporal clustering of discovery commands
- Delay between lateral movement and secondary callback

---

## Evidence Confidence

Not all evidence carries equal weight. Apply confidence levels:

| Level | Criteria |
|---|---|
| High | Direct telemetry with verified ECS mapping; event confirmed on both source and target |
| Medium | Single-source telemetry with consistent context; logically connected to adjacent events |
| Low | Inferred from timing or proximity; no direct event linking the actions |
| Gap | Expected telemetry not available; known sensor or ingest limitation |

Document confidence for each link in the reconstruction chain.

---

## Completed Investigation: Detection #1

### Observed Chain

```text
C0015\duc.user on WS01
  → tasklist.exe
  → net.exe / net1.exe account-group discovery
  → nltest.exe domain-trust discovery
  → net view \\FS01
  → SMB access to \\FS01\Finance\budget-q3.txt
```

Discovery activity observed through Sysmon Process Create telemetry on WS01. Collection confirmed independently on FS01 with Windows Security Event ID 5145.

### Server-Side Evidence

Event ID 5145 on FS01:

- Account: `C0015\duc.user`
- Source address: `192.168.50.20`
- Share: `\\*\Finance`
- Target: `budget-q3.txt`
- Local path: `C:\Shares\Finance\budget-q3.txt`
- Access: successful `ReadData`

### Correlation Result

The ES|QL correlation produced one Medium-severity alert (risk score 60) after five atomic behavior families fired within the investigation window.

Correlation grouped by `user.name`, required collection activity, required multiple hosts, and used distinct behavior families to avoid double-counting duplicate atomic alerts.

### Analyst Workflow

1. Validate the user and source workstation
2. Inspect the discovery sequence and parent processes
3. Pivot to FS01 5145 events
4. Confirm the remote target and accessed files
5. Review whether the access was expected for the identity
6. Search for follow-on lateral movement, staging, exfiltration, or persistence

### Known Limitation

The correlation proves same-user, multi-host activity with a source IP present, but does not yet mathematically join the FS01 `source.ip` back to the exact WS01 host identity. This is a future enrichment/correlation improvement.

---

## Completed Investigation: Phase 1 Bootstrap Chain

### Overview

Phase 1 reconstructs the C0015 bootstrap/Bazar-stage chain using a benign SAFE SUBSTITUTE. The investigation traces the full causal chain from document execution through DLL load and code execution, using ProcessGuid/entity_id where available and PID-based correlation where necessary.

### Causal Graph

```text
explorer.exe
  │
  ▼
WINWORD.EXE (PID 2288)
  │  evidence: OBSERVED — Sysmon EID 1
  ▼
cmd.exe (PID 5564)
  │  evidence: OBSERVED — Sysmon EID 1, parent = WINWORD.EXE
  ▼
mshta.exe (PID 6592)
  │  evidence: OBSERVED — Sysmon EID 1, parent = cmd.exe
  │
  ├──▶ TCP → 192.168.50.100:8000
  │       evidence: OBSERVED — Sysmon EID 3 (PID 6032)
  │       + Kali HTTP 200
  │       NOTE: process attribution is INFERRED (see P1-B below)
  │
  ├──▶ FileCreate: downloaded-marker.txt
  │       evidence: OBSERVED — Sysmon EID 11 (PID 6032, Image=mshta.exe)
  │
  ├──▶ FileCreate: c0015-marker.dll
  │       evidence: OBSERVED — Sysmon EID 11
  │       (mshta.exe PID 3604, entity_id {88E52A21-F5AB-6AAD-CF01-000000001500})
  │
  ▼
regsvr32.exe (PID 5872)
  │  entity_id: {88E52A21-F5AB-6AAD-D001-000000001500}
  │  parent: mshta.exe PID 3604, entity_id {88E52A21-F5AB-6AAD-CF01-000000001500}
  │  evidence: OBSERVED — Sysmon EID 1
  │
  ├──▶ ImageLoad: c0015-marker.dll
  │       SHA-256: d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544
  │       Signed: false
  │       evidence: OBSERVED — Sysmon EID 7 (same entity_id, same hash as Kali artifact)
  │
  ▼
DllRegisterServer()
  │  evidence: OBSERVED — regsvr32.exe created dll-executed.txt (Sysmon EID 11, same entity_id)
  ▼
dll-executed.txt
```

### Evidence Confidence

| Link | Confidence | Basis |
|---|---|---|
| WINWORD.EXE → cmd.exe | High | Direct Sysmon EID 1 parent-child |
| cmd.exe → mshta.exe | High | Direct Sysmon EID 1 parent-child |
| mshta.exe → TCP 192.168.50.100:8000 (P1-B) | Medium | PID correlation — see P1-B analysis below |
| mshta.exe → FileCreate downloaded-marker.txt | High | Direct Sysmon EID 11 with Image=mshta.exe |
| mshta.exe → FileCreate c0015-marker.dll | High | Direct Sysmon EID 11 with entity_id |
| mshta.exe → regsvr32.exe | High | Direct Sysmon EID 1 parent-child with entity_id |
| regsvr32.exe → ImageLoad c0015-marker.dll | High | Direct Sysmon EID 7 with entity_id and hash match |
| regsvr32.exe → dll-executed.txt | High | Direct Sysmon EID 11 with entity_id |
| DLL retrieval network transfer (P1-C) | Gap | No Sysmon EID 3 for final DLL retrieval; server-side evidence only |

### P1-B PID Correlation Analysis

The Sysmon Event ID 3 network connection event for P1-B contained:

- `Image = <unknown process>`
- `ProcessGuid = {00000000-0000-0000-0000-000000000000}` (null)
- PID: 6032

Event ID 3 did **not** directly identify the process. The attribution to mshta.exe is INFERRED from:

1. **PID match:** PID 6032 appears in both the EID 3 network event and the subsequent EID 11 FileCreate event, where `Image = C:\Windows\System32\mshta.exe` was recorded.
2. **Temporal proximity:** The network connection (01:23:48.766Z) preceded the file creation (01:23:52.680Z) by approximately four seconds.
3. **Server-side evidence:** Kali independently recorded the HTTP GET from 192.168.50.20.
4. **Causal consistency:** The file created (`downloaded-marker.txt`) is the expected artifact of the HTTP retrieval.

This is a valid investigative correlation but must be documented as INFERRED, not as direct sensor identification.

### P1-C Sensor Gap

No Sysmon Event ID 3 was captured on WS01 for the final P1-C DLL retrieval (`GET /c0015-marker.dll`). The transfer is proven by:

- Server-side HTTP 200 log from Kali
- Sysmon EID 11 FileCreate for `c0015-marker.dll` on WS01
- Sysmon EID 7 ImageLoad confirming the DLL hash matches the Kali artifact
- Sysmon EID 1 ProcessCreate for regsvr32.exe loading the DLL

The sensor gap demonstrates a real-world limitation: network-level telemetry may be incomplete even when process and file telemetry provides sufficient evidence to reconstruct the chain. Detection strategies should not depend solely on Event ID 3 for network transfer visibility.

### Timing Limitation

Cross-host timestamps are not precisely synchronized. Windows/Sysmon UTC events cluster around 2026-09-19 02:38 UTC; Kali HTTP logs show approximately 18/Sep/2026 22:38. The Kali clock skew remains unresolved. Absolute cross-host timing analysis is unreliable until synchronization is corrected.

### Investigation Queries

Process chain (all Phase 1 processes):

```kql
host.name:"ws01" and event.code:"1" and
(
  process.name:"WINWORD.EXE" or
  process.name:"cmd.exe" or
  process.name:"mshta.exe" or
  process.name:"regsvr32.exe"
)
```

regsvr32 execution:

```kql
host.name:"ws01" and
event.code:"1" and
process.name:"regsvr32.exe"
```

DLL written to disk:

```kql
host.name:"ws01" and
event.code:"11" and
file.name:"c0015-marker.dll"
```

DLL ImageLoad:

```kql
host.name:"ws01" and
event.code:"7" and
file.name:"c0015-marker.dll"
```

Execution marker:

```kql
host.name:"ws01" and
event.code:"11" and
file.name:"dll-executed.txt"
```

Network connections to Kali HTTP server:

```kql
host.name:"ws01" and
event.code:"3" and
destination.ip:"192.168.50.100" and
destination.port:8000
```

---

## Investigation Roadmap

As additional campaign stages are reconstructed, the investigation methodology will expand to cover:

- ~~Bootstrap → Bazar → Cobalt Strike process chain reconstruction~~ (Phase 1 bootstrap complete)
- WMI lateral-movement provenance (source host → authentication → target process)
- Collection-to-transfer timeline analysis
- RDP session analysis and operator activity reconstruction
- Impact scope assessment (files/bytes modified, directories affected)
- Containment effectiveness (time from detection to containment, residual activity)

Each new stage adds pivot points and cross-host evidence links that strengthen or weaken the overall intrusion narrative.

**Phase 2 handoff:** Phase 2 will begin from this verified Phase 1 baseline. The bootstrap chain provides the validated process ancestry and telemetry foundation for the Bazar-stage callback and CALDERA tasking integration.


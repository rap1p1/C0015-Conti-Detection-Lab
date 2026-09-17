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

## Investigation Roadmap

As additional campaign stages are reconstructed, the investigation methodology will expand to cover:

- Bootstrap → Bazar → Cobalt Strike process chain reconstruction
- WMI lateral-movement provenance (source host → authentication → target process)
- Collection-to-transfer timeline analysis
- RDP session analysis and operator activity reconstruction
- Impact scope assessment (files/bytes modified, directories affected)
- Containment effectiveness (time from detection to containment, residual activity)

Each new stage adds pivot points and cross-host evidence links that strengthen or weaken the overall intrusion narrative.

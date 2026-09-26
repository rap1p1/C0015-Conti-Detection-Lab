# C0015 Purple Lab — Project Build Plan

> **Status note (2026-09-26+):** This file records the **original 0–11 build plan** and is kept for historical
> traceability. The **canonical phase numbering is now 0–15**, defined in
> [`docs/attack-chain-plan.md`](attack-chain-plan.md) (mục 10–13), with the OLD→NEW mapping table. Evidence status of every phase is tracked in
> [`docs/evidence-matrix-v2.md`](evidence-matrix-v2.md); artifact handoff contracts in
> [`docs/handoff-contracts.md`](handoff-contracts.md); correlation design in
> [`docs/correlation-architecture.md`](correlation-architecture.md). This file is **not** updated to reflect the
> revised numbering, to preserve history.

## Project Objective

Build a threat-informed purple-team lab that reconstructs the publicly documented C0015 intrusion chain while preserving the campaign's three defining software stages:

- **Bazar**
- **Cobalt Strike**
- **Conti**

The project will not rely on running the original malware. Instead, each stage will be reconstructed with controlled, observable equivalents so the lab can generate real Windows, authentication, process, file, and network telemetry for detection engineering.

The target workflow is:

```text
C0015 public evidence
        ↓
behavioral specification
        ↓
safe live reconstruction
        ↓
raw telemetry
        ↓
baseline detection
        ↓
controlled variation
        ↓
detection gap analysis
        ↓
improved analytics
        ↓
containment and recovery validation
```

The project is not intended to be an ATT&CK checklist. Each emulated behavior must contribute to the reconstructed intrusion story.

---

## 1. Evidence Model

Every campaign claim will be classified before implementation.

| Classification | Meaning |
|---|---|
| **OBSERVED** | Directly supported by a campaign source or artifact. |
| **INFERRED** | Reasoned from available evidence, with uncertainty documented. |
| **UNKNOWN** | Evidence is insufficient; the gap remains unresolved. |
| **LAB ASSUMPTION** | A prerequisite introduced only to make the lab executable. |
| **SUPPLEMENTAL** | Additional experiment that is useful for learning but is not counted as core C0015 coverage. |

Each ATT&CK technique used in the project will track:

- ATT&CK ID
- whether it is recorded for C0015
- historical procedure
- lab implementation
- fidelity level
- expected telemetry
- detection coverage
- known limitations

Supplemental techniques will never be counted as C0015 core coverage.

---

## 2. Primary Sources

The reconstruction will be grounded in:

1. MITRE ATT&CK Campaign C0015
2. MITRE ATT&CK software entries for Bazar, Cobalt Strike, and Conti
3. The DFIR Report case study *CONTInuing the Bazar Ransomware Story*
4. Available PCAP, EVTX, Sysmon, KAPE, memory, or file artifacts when legally obtained
5. Other Bazar/Conti incidents only as contextual references, never as automatic evidence for C0015

Source disagreements will be documented instead of silently reconciled.

---

## 3. Lab Architecture

### Network

```text
VMnet2 — 192.168.50.0/24
Host-only
DHCP disabled
```

### Systems

| Host | Role |
|---|---|
| `DC01` — `192.168.50.10` | Active Directory, DNS, authentication telemetry |
| `WS01` — `192.168.50.20` | Initial victim workstation |
| `FS01` — `192.168.50.30` | File server, lateral-movement target, backup-role surrogate |
| `Kali` — `192.168.50.100` | Operator host, routing, lab tooling |
| `ELASTIC01` | Elasticsearch, Kibana, Fleet |
| Windows host — `192.168.50.1` | VMware host and optional lab-side service host |

Windows endpoints will not use a normal Internet default gateway. Telemetry traffic to Elastic will traverse the controlled lab route.

---

## 4. Core Tooling

### Apache CALDERA

CALDERA will provide:

- campaign orchestration
- controlled agents
- task scheduling
- adversary profiles
- operation replay
- task/result logging

It will serve as the tasking/orchestration layer for the Bazar and Cobalt Strike reconstruction stages.

### Atomic Red Team

Atomic Red Team will be used for reviewed Windows primitives such as:

- discovery
- WMI execution
- LOLBin execution
- selected remote-execution behaviors
- baseline ATT&CK validation

Each atomic test will be reviewed before execution for:

- dependencies
- cleanup behavior
- privilege requirements
- network destinations
- payloads
- filesystem impact

### Custom Lab Components

Custom code will only be created where existing frameworks do not reproduce the required C0015 evidence shape.

Expected custom components:

```text
bootstrap DLL
controlled tasking wrapper
lab-owned injection target
benign lateral-stage DLL
bounded impact simulator
```

---

## 5. Telemetry Foundation

No emulation phase begins until telemetry is validated.

### Sysmon

Primary event classes include:

- Process creation
- Network connections
- File creation
- Registry activity
- Named pipes
- WMI activity
- DNS queries

For the injection experiments, additional visibility will be enabled where required for:

- image/module loading
- process access
- remote-thread-related observations when applicable

### Windows Security Logging

Enable only the auditing needed for each experiment, including:

- successful and failed logons
- explicit credential use
- privileged logon
- RDP activity
- SMB share access
- object access on the bounded impact corpus
- WMI activity
- PowerShell logging when PowerShell is used

### Phase Gate

Before any attack-emulation step:

```text
local event exists
→ Elastic Agent ingests it
→ ECS mapping is correct
→ query retrieves it
→ ingest delay is measured
```

If telemetry is missing, the sensor is fixed before detection logic is written.

---

# 6. Build Phases

## Phase 0 — Ground Truth and Sensor Readiness

### Goals

- freeze the campaign evidence baseline
- create the Evidence Ledger
- validate AD, DNS, time synchronization, routing, and Fleet
- verify endpoint telemetry
- record the privilege matrix
- define the packet-capture point for each network experiment

### Deliverables

```text
evidence-ledger.md
sensor-matrix.md
privilege-matrix.md
network-visibility-map.md
```

---

## Phase 1 — Initial Access and Bootstrap Reconstruction

### Historical Goal

Reconstruct the user-execution and bootstrap relationships that led into the Bazar stage.

### Lab Flow

```text
document
→ user execution
→ HTA/script bootstrap
→ user-writable artifact
→ proxy execution / DLL loading
→ benign DLL
→ outbound callback
```

### Fidelity Priorities

Preserve where possible:

- parent/child relationships
- user context
- file-path class
- DLL load relationship
- process-to-network timing
- artifact creation

### Detection Objective

Build a causal analytic around:

```text
document/script execution
→ unusual artifact
→ proxy execution or DLL load
→ network activity
```

### Control Runs

- normal document activity
- legitimate administrative DLL execution

---

## Phase 2 — Bazar Stage Reconstruction

The phase remains explicitly identified as the **Bazar stage**.

### Lab Behavior

The Bazar surrogate will:

- receive execution from the bootstrap stage
- perform a public-IP-style lookup against an internal mock service
- initiate a controlled callback
- transition into the tasking layer
- use bounded retry/sleep behavior

It will not provide arbitrary shell execution.

### Detection Objective

Detect relationships rather than filenames:

```text
unusual process/module
→ network callback
→ downstream discovery
```

### Persistence Handling

No Run Key, Scheduled Task, or Service persistence will be added to the C0015 core unless campaign evidence supports it.

If persistence is later studied, it will be a separate supplemental experiment.

---

## Phase 3 — Cobalt Strike Stage Reconstruction

The phase remains explicitly identified as the **Cobalt Strike stage**.

### Lab Behavior

A controlled CALDERA agent or equivalent fixed-task agent will reproduce:

```text
callback
→ task retrieval
→ predefined action
→ result
→ sleep
→ next callback
```

Allowed task categories will include only the actions needed for the campaign reconstruction, such as:

```text
DISCOVERY_ACCOUNT
DISCOVERY_DOMAIN
DISCOVERY_HOST
DISCOVERY_SHARE
NETWORK_INFO
WMI_LAB_STAGE
COLLECT_LAB_CORPUS
```

### Measurements

Record:

- callback cadence
- retry behavior
- task-to-process delay
- process ancestry
- result-to-next-callback delay
- network destination

Detection will not depend on one hard-coded beacon interval.

---

## Phase 4 — Discovery and Target Selection

The project already has baseline discovery telemetry and detections. These will now be used as part of the intrusion decision process rather than isolated ATT&CK exercises.

### Discovery Questions

```text
Who am I?
What domain am I in?
What groups exist?
What hosts exist?
What shares are available?
What data is readable?
Which host is operationally valuable?
```

### Expected Behaviors

- process discovery
- domain group discovery
- trust discovery
- remote-system discovery
- network-configuration discovery
- share discovery
- SMB file access

The output of discovery should explain why `FS01` becomes the lateral-movement target.

---

## Phase 5 — Privileged Access Prerequisite

The public C0015 evidence does not establish how the required remote administrative credential was obtained.

The lab will therefore state explicitly:

```text
LAB ASSUMPTION:
The operator already possesses an account authorized on FS01.
```

The account will:

- have only the rights required on FS01
- not be Domain Admin
- not be local admin on WS01
- not be local admin on DC01

Validation cases:

```text
normal user → denied
authorized lab account → allowed
revoked account → denied
```

This phase studies authentication and authorization, not credential acquisition.

---

## Phase 6 — WMI Lateral Movement

### Historical Relationship

```text
WS01
→ WMI remote execution
→ target server
→ rundll32 / DLL stage
→ additional Cobalt Strike foothold
```

### Lab Flow

```text
WS01
→ WMI/DCOM
→ FS01
→ approved benign process/DLL
→ second controlled agent callback
```

### Evidence Collection

Source-side:

- initiating process
- network/RPC activity
- explicit credential-use evidence where available

Target-side:

- logon event
- WMI event
- process creation
- file/module evidence
- new callback originating from FS01

### Detection Objective

Correlate:

```text
workstation source
+ privileged authentication
+ remote execution
+ unusual target process/module
+ post-execution callback
```

### Completion Gate

The phase is complete only if it proves:

- the process executed on FS01
- which identity was used
- which process was created
- that the new callback originated from FS01

---

## Phase 7 — Controlled DLL Injection Reconstruction

### Historical Anchor

C0015 includes DLL injection into legitimate Windows processes during the Bazar/Cobalt Strike chain.

### Lab Flow

```text
benign loader
→ cross-process DLL injection
→ lab-owned target process
→ benign observable behavior
```

The target will be a process owned by the lab rather than a sensitive Windows process.

### Fidelity Reporting

```text
ATT&CK mechanism: reproduced
exact original target process: not reproduced
mechanism fidelity: high
target fidelity: partial
```

### Telemetry

Collect:

- process access
- source/target relationship
- module-load evidence
- target-side behavior
- network callback if part of the experiment

A marker file alone is not sufficient evidence of successful injection.

---

## Phase 8 — Collection and Transfer

### Historical Anchor

C0015 involved share discovery, data collection, Rclone, and transfer to cloud storage.

### Lab Corpus

Create a dummy dataset with:

- known file count
- known total size
- hashes
- ACLs
- Finance and IT sample data

### Lab Flow

```text
SMB read
→ controlled collection
→ optional staging
→ Rclone or equivalent
→ internal controlled destination
```

If the destination is not real cloud storage, the fidelity for cloud-storage exfiltration is documented as partial.

### Detection Objective

Correlate:

```text
share access
→ collection process
→ outbound transfer
→ transfer volume
```

### Metrics

- files read
- bytes read
- files transferred
- bytes transferred
- time to detection
- bytes transferred before containment

---

## Phase 9 — RDP and Secondary Remote Access

### Lab Behavior

Use real RDP between lab systems and capture:

- session creation
- reconnect/disconnect
- interactive logon
- process activity during the session

AnyDesk-related behavior will be handled through historical evidence or an internal equivalent rather than relying on public relay infrastructure.

### Detection Objective

Distinguish:

```text
ordinary network logon
remote interactive logon
legitimate administration
remote access embedded in a prior intrusion chain
```

---

## Phase 10 — Conti Impact Reconstruction

The phase remains explicitly identified as the **Conti impact stage**.

The original Conti binary will not be used.

### Lab Corpus

The impact simulator will operate only against a disposable, pre-generated corpus with a manifest.

### Hard Boundaries

The simulator must enforce:

- exact allowlisted root
- lab marker requirement
- maximum file count
- maximum byte count
- maximum execution time
- no drive root
- no Windows/system directories
- no arbitrary UNC target
- no reparse/symlink escape
- no SYSTEM execution
- no self-propagation

### Lab Behavior

```text
enumerate dummy files
→ high-rate controlled file transformations
→ rename / extension changes
→ optional bounded replacement/delete
→ note creation
→ local impact run
→ separate SMB impact run
```

### Detection Objective

Detect behavioral invariants such as:

- modification breadth
- modification rate
- number of affected directories
- local versus SMB scope
- account/process context
- repeated note creation
- unusual fan-out

### Legitimate Controls

Compare against:

- backup
- archive extraction
- software build output
- synchronization
- administrative bulk file operations

---

## Phase 11 — Prevention, Containment, and Recovery

### Prevention Tests

Evaluate controls such as:

- Office protection
- LOLBin restrictions
- least privilege
- WMI policy
- RDP policy
- SMB segmentation
- endpoint hardening

### Containment

Use available lab controls to:

- terminate the controlled process
- disable/revoke the lab account
- block SMB access
- block the relevant network flow
- isolate the endpoint when supported

### Timeline Metrics

Track:

```text
behavior start
→ event generated
→ event ingested
→ atomic detection
→ correlation
→ analyst action
→ containment effective
```

### Recovery

Restore the impact corpus from a protected backup and verify:

- file count
- hashes
- ACLs
- recovery time

VM snapshots are used only for lab reset, not as the enterprise recovery model.

---

# 7. Detection Architecture

## Atomic Analytics

Atomic detections remain useful as building blocks and regression tests.

Existing examples include:

- Windows command shell
- process discovery
- domain group discovery
- domain trust discovery
- network share discovery
- remote system discovery
- network configuration discovery
- SMB file read

## Higher-Level Correlations

### C1 — Discovery to SMB Collection

Existing cross-host behavior correlation retained as a regression analytic.

### C2 — Bootstrap / Foothold

```text
document/script
→ proxy execution or DLL
→ unusual network activity
```

### C3 — Identity / WMI Pivot

```text
source host
→ privileged authentication
→ WMI remote execution
→ target process
→ new callback
```

### C4 — Collection / Transfer

```text
SMB access
→ collecting process
→ outbound transfer
```

### C5 — Injection Suspicion

```text
source process
→ target process access
→ module/target behavior
```

### C6 — Impact

```text
process/account
→ high-rate file activity
→ broad local/SMB scope
```

---

# 8. Detection Engineering Loop

Every experiment follows the same workflow:

1. Define the detection hypothesis.
2. Record the lab state and configuration.
3. Run a legitimate control.
4. Run the target behavior.
5. Validate local telemetry.
6. Validate Elastic ingestion and field mapping.
7. Let the actual scheduled analytic execute.
8. Record the result.
9. Change one meaningful observable.
10. Re-run the experiment.
11. Improve the analytic if it misses.
12. Re-run target and control cases.
13. Close the experiment with evidence.

Allowed result states:

```text
NOT RUN
BLOCKED BY ENVIRONMENT
PREVENTED
SENSOR GAP
INGEST/MAPPING GAP
DETECTION MISS
DETECTED
PARTIAL
```

---

# 9. Measurement Framework

The project will report more than alert counts.

| Area | Measurement |
|---|---|
| Fidelity | Which historical mechanism was preserved or changed |
| Visibility | Whether expected telemetry was generated and ingested |
| Detection | Detection rate across valid target runs |
| False positives | Behavior on legitimate control runs |
| Latency | Behavior → ingest → alert → containment |
| Lateral movement | Source → identity → target process → callback |
| Transfer | Files/bytes transferred before detection and containment |
| Impact | Files/bytes modified before containment |
| Recovery | Restore accuracy and recovery time |
| Investigation | Whether the analyst can explain actor, host, account, process, and data relationships |

---

# 10. Evidence Handling

## Report Evidence

Only evidence that helps explain the intrusion story belongs in the final report.

Priority examples:

- bootstrap/Bazar causal chain
- Cobalt Strike-like task/callback relationship
- WMI pivot with authentication provenance
- one detector miss followed by an improved analytic
- collection/transfer correlation
- Conti impact metrics
- containment and recovery results

## Repository-Only Evidence

Keep lower-level validation in the repository:

- atomic alert screenshots
- mapping checks
- individual event expansions
- troubleshooting notes
- intermediate queries

Prefer structured evidence over screenshots:

- sanitized JSON
- timestamps
- rule definitions
- query text
- configuration hashes
- diagrams

---

# 11. Repository Structure

```text
C0015-Conti-Detection-Lab/
├── README.md
├── plan.md
├── configs/
│   ├── elastic/
│   ├── fleet/
│   └── sysmon/
├── detections/
│   ├── atomic/
│   ├── correlations/
│   └── eql/
├── diagrams/
├── docs/
│   ├── architecture.md
│   ├── detection-engineering.md
│   ├── experiments.md
│   ├── investigation.md
│   └── lab-journal.md
├── evidence/
│   └── sanitized-screenshots/
└── scripts/
```

Repository rules:

- do not store credentials or secrets
- do not store malware binaries
- do not store sensitive credential dumps
- sanitize screenshots and logs before commit
- inspect existing detection files before creating new ones
- run a secret scan before committing

---

# 12. End-to-End Exercise

Once all phases pass independently, run the complete campaign reconstruction:

```text
Initial execution
→ Bazar stage
→ Cobalt Strike stage
→ discovery
→ privileged-access prerequisite
→ WMI lateral movement
→ second foothold
→ collection
→ transfer
→ RDP / secondary access
→ Conti impact
→ containment
→ recovery
```

Two complete runs will be performed.

## Engineering Run

Purpose:

- validate stage handoffs
- compress the timeline
- confirm telemetry continuity
- confirm detection dependencies

## Investigation Run

Purpose:

- hide the task log until the investigation is complete
- start from the strongest alert
- reconstruct the intrusion backward and forward
- compare analyst reconstruction with the ground truth

The original multi-day campaign timing remains part of the historical narrative; the lab execution may be compressed.

---

# 13. Definition of Done

The project is complete when:

- the Evidence Ledger clearly separates observed, inferred, unknown, and lab-assumed behavior
- Bazar, Cobalt Strike, and Conti remain visible as the three campaign anchors
- the bootstrap chain produces live telemetry
- the controlled tasking layer produces measurable callback/task/process relationships
- discovery leads to a documented target-selection decision
- the lab proves authentication → WMI → remote execution → new callback
- controlled DLL injection is reproduced or explicitly documented as partial
- collection and transfer are reproduced with measurable file/byte counts
- RDP/remote-access telemetry is analyzed
- the bounded Conti impact experiment is completed
- containment and recovery metrics are recorded
- at least one baseline detector is shown to miss a controlled variation and is improved
- telemetry gaps are documented rather than hidden
- no technique is claimed based only on a filename, tool name, or marker
- supplemental experiments do not inflate C0015 coverage
- limitations are explicit in the final report

---

# 14. Build Order

The project will be built in this order:

```text
1. Freeze C0015 ground truth
2. Build the Evidence Ledger
3. Validate sensors and network visibility
4. Validate CALDERA with one harmless task
5. Build the bootstrap chain
6. Build the Bazar-stage surrogate
7. Build the Cobalt Strike-stage tasking flow
8. Connect discovery to target selection
9. Validate the privileged-access prerequisite
10. Reconstruct WMI lateral movement
11. Reconstruct controlled DLL injection
12. Reconstruct collection and transfer
13. Reconstruct RDP / secondary remote access
14. Build the bounded Conti impact stage
15. Build containment and recovery tests
16. Run detection-robustness experiments
17. Run the full engineering exercise
18. Run the full investigation exercise
19. Finalize report, diagrams, evidence, and repository
```

This order is intentionally dependency-driven: no phase proceeds until the telemetry and prerequisite relationships required by the next phase are proven.

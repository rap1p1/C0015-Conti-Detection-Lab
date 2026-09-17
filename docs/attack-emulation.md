# Attack Emulation

## Overview

This document defines the C0015 intrusion lifecycle reconstruction. Each section corresponds to a stage of the documented campaign, not to isolated ATT&CK technique exercises.

The lab does not execute original Bazar, Cobalt Strike, or Conti binaries. Each stage is reconstructed with controlled surrogates that preserve the historical role, Windows/network mechanisms, and causal relationships of the original campaign.

---

## 1. Initial Execution / Bootstrap

### Historical Evidence

C0015 began with user execution of a document or script that triggered an HTA/script-based bootstrap chain. This chain wrote artifacts to user-writable locations and loaded a DLL through proxy execution mechanisms, leading into the Bazar stage.

**Evidence classification:** OBSERVED (document execution → DLL loading chain documented in campaign reports)

### Lab Implementation

```text
document → user execution → HTA/script bootstrap → user-writable artifact
  → proxy execution / DLL loading → benign DLL → outbound callback
```

A controlled bootstrap chain will reproduce the parent/child process relationships, user context, file-path class, DLL load relationship, and process-to-network timing of the original chain.

### Expected Telemetry

- Process creation chain (Sysmon Event ID 1)
- File creation in user-writable paths (Sysmon Event ID 11)
- DLL/module load events
- Network connection following DLL load (Sysmon Event ID 3)

### Detection Objective

Build a causal analytic correlating: document/script execution → unusual artifact → proxy execution or DLL load → network activity.

### Fidelity

- Parent/child relationships: preserved
- User context: preserved
- File-path class: preserved
- DLL load mechanism: preserved
- Actual malware payload: not used

### Limitations

The bootstrap artifacts are benign. The DLL contains no malicious functionality. Detection must rely on behavioral relationships rather than payload signatures.

---

## 2. Bazar Stage Reconstruction

### Historical Evidence

Bazar served as the initial implant after the bootstrap chain. It performed environment checks (including a public IP lookup), established a callback channel, and eventually transitioned control to the Cobalt Strike stage.

**Evidence classification:** OBSERVED (Bazar behavior documented in C0015 and DFIR Report)

### Lab Implementation

The Bazar surrogate will:

- Receive execution from the bootstrap stage
- Perform a public-IP-style lookup against an internal mock service
- Initiate a controlled callback
- Transition into the CALDERA tasking layer
- Use bounded retry/sleep behavior

The surrogate does not provide arbitrary shell execution.

### Expected Telemetry

- Process creation from bootstrap parent
- DNS query to internal mock service
- Outbound network connection (callback)
- Process-to-process handoff to the tasking layer

### Detection Objective

Detect behavioral relationships rather than filenames: unusual process/module → network callback → downstream discovery.

### Fidelity

- Historical role: Bazar initial implant — preserved
- Environment check: reproduced against internal service
- Callback mechanism: controlled equivalent
- Runtime/binary: not used

### Limitations

No Run Key, Scheduled Task, or Service persistence is part of the core reconstruction unless campaign evidence supports it. Persistence is a potential supplemental experiment.

---

## 3. Cobalt Strike Stage Reconstruction

### Historical Evidence

Cobalt Strike Beacon provided the operators with command-and-control tasking, discovery execution, and lateral-movement orchestration during C0015.

**Evidence classification:** OBSERVED (Cobalt Strike usage documented in C0015 and DFIR Report)

### Lab Implementation

A controlled CALDERA agent (or equivalent fixed-task agent) reproduces the Cobalt Strike tasking workflow:

```text
callback → task retrieval → predefined action → result → sleep → next callback
```

Allowed task categories:

```text
DISCOVERY_ACCOUNT
DISCOVERY_DOMAIN
DISCOVERY_HOST
DISCOVERY_SHARE
NETWORK_INFO
WMI_LAB_STAGE
COLLECT_LAB_CORPUS
```

### Expected Telemetry

- Periodic callback network connections
- Task-driven process creation
- Process ancestry linking callback agent to discovery commands
- Result-to-callback timing

### Detection Objective

Record and analyze: callback cadence, retry behavior, task-to-process delay, process ancestry, result-to-next-callback delay, network destination. Detection must not depend on a single hard-coded beacon interval.

### Fidelity

- Historical role: Cobalt Strike Beacon C2 — preserved
- Tasking/callback workflow: reproduced via CALDERA
- Beacon binary/protocol: not used
- Lab surrogate: controlled tasking/orchestration surrogate reconstructing the Cobalt Strike role

### Limitations

CALDERA is not Cobalt Strike. It reproduces the command-and-control workflow with observable, bounded operations. Cobalt Strike-specific protocol artifacts (e.g., Malleable C2 profiles, named-pipe SMB beacons) are not generated.

---

## 4. Discovery and Target Selection

### Historical Evidence

C0015 operators performed systematic discovery to identify domain structure, available shares, accessible data, and operationally valuable targets before lateral movement.

**Evidence classification:** OBSERVED (discovery techniques documented in C0015)

### Lab Implementation

**Completed behaviors:**

| Technique | Emulation | Status |
|---|---|---|
| T1059.003 Windows Command Shell | Interactive `cmd.exe` activity | DETECTED |
| T1057 Process Discovery | `tasklist` | DETECTED |
| T1069.002 Domain Groups Discovery | `net group "Domain Admins" /domain` | DETECTED |
| T1482 Domain Trust Discovery | `nltest /domain_trusts /all_trusts` | DETECTED |
| T1135 Network Share Discovery | `net view \\FS01` | DETECTED |
| T1039 Data from Network Shared Drive | Read files from `\\FS01\Finance` | DETECTED |

**Planned behaviors:**

| Technique | Emulation | Status |
|---|---|---|
| T1018 Remote System Discovery | Network host enumeration | NOT RUN |
| T1016 System Network Configuration Discovery | `ipconfig`, `route` | NOT RUN |

### Expected Telemetry

- Sysmon Process Create events on WS01
- Windows Security Event ID 5145 on FS01 (SMB file access)
- ECS-normalized process, user, host, and file fields

### Detection Objective

Discovery is not detected in isolation. The output of discovery should explain why FS01 becomes the lateral-movement target. The discovery-to-collection correlation (C1) is the first validated cross-host analytic.

### Fidelity

Discovery commands reproduce the documented C0015 procedures using the same native Windows utilities.

### Limitations

Discovery alone does not prove malicious intent. The correlation requires collection activity and multi-host context to increase confidence.

---

## 5. Privileged-Access Lab Prerequisite

### Historical Evidence

The public C0015 evidence does not establish how the required remote administrative credential was obtained before WMI lateral movement.

**Evidence classification:** UNKNOWN

### Lab Implementation

```text
LAB ASSUMPTION:
The operator already possesses an account authorized on FS01.
```

The lab account will:

- Have only the rights required on FS01
- Not be Domain Admin
- Not be local admin on WS01 or DC01

Validation cases:

```text
normal user       → denied
authorized account → allowed
revoked account   → denied
```

### Expected Telemetry

- Windows Security logon events (4624, 4625)
- Explicit credential use events
- Privileged logon events (4672)

### Detection Objective

This phase studies authentication and authorization boundaries, not credential acquisition. LSASS credential dumping is not part of the main causal chain.

### Fidelity

- Authentication mechanism: reproduced
- Credential provenance: UNKNOWN — not reproduced

### Limitations

The lab cannot reconstruct what it does not know. The credential acquisition method remains an acknowledged gap in the C0015 evidence.

---

## 6. WMI Lateral Movement

### Historical Evidence

C0015 operators used WMI to execute a DLL-based stage on the target server, establishing a second Cobalt Strike foothold.

```text
WS01 → WMI remote execution → target server → rundll32 / DLL stage
  → additional Cobalt Strike foothold
```

**Evidence classification:** OBSERVED (WMI lateral movement documented in C0015)

### Lab Implementation

```text
WS01 → WMI/DCOM → FS01 → approved benign process/DLL
  → second controlled agent callback
```

### Expected Telemetry

**Source-side (WS01):**
- Initiating process creation
- Network/RPC activity toward FS01
- Explicit credential use events

**Target-side (FS01):**
- Logon event (4624 Type 3)
- WMI event subscription or process creation
- Process creation (wmiprvse.exe → target process)
- File/module load evidence
- New outbound callback from FS01

### Detection Objective

Correlate: workstation source + privileged authentication + remote WMI execution + unusual target process/module + post-execution callback.

### Fidelity

- WMI mechanism: reproduced
- DLL stage on target: benign equivalent
- Second callback: controlled agent
- Historical role: preserved

### Limitations

The benign DLL does not contain Cobalt Strike Beacon functionality. Detection relies on the execution mechanism and process relationships, not payload content.

**Completion gate:** The phase proves (1) the process executed on FS01, (2) which identity was used, (3) which process was created, and (4) the new callback originated from FS01.

---

## 7. Controlled DLL Injection Reconstruction

### Historical Evidence

C0015 includes DLL injection into legitimate Windows processes during the Bazar/Cobalt Strike chain.

**Evidence classification:** OBSERVED (DLL injection documented in C0015)

### Lab Implementation

```text
benign loader → cross-process DLL injection → lab-owned target process
  → benign observable behavior
```

The target is a process owned by the lab, not a sensitive Windows system process (LSASS, Winlogon, system svchost).

### Expected Telemetry

- Process access events (Sysmon Event ID 10)
- Source/target process relationship
- Module load evidence
- Target-side behavior changes

### Detection Objective

Detect: source process → target process access → module/target behavior. A marker file alone is not sufficient evidence of successful injection.

### Fidelity

```text
ATT&CK mechanism:          reproduced
Exact original target:      not reproduced (lab-owned target)
Mechanism fidelity:         high
Target fidelity:            partial
```

### Limitations

Injection into LSASS, Winlogon, or system svchost is not performed. The target process is lab-controlled. Detection of injection into high-privilege system processes requires different visibility than what this experiment generates.

---

## 8. Collection and Transfer

### Historical Evidence

C0015 involved share discovery, data collection, and transfer to cloud storage using Rclone.

**Evidence classification:** OBSERVED (Rclone and collection documented in C0015 and DFIR Report)

### Lab Implementation

A bounded dummy dataset is created with known file count, total size, hashes, and ACLs across Finance and IT sample data.

```text
SMB read → controlled collection → optional staging
  → Rclone or equivalent → internal controlled destination
```

### Expected Telemetry

- Windows Security 5145 events (SMB file access on FS01)
- Process creation for collection and transfer tools
- Network connections to transfer destination
- File creation at staging location

### Detection Objective

Correlate: share access → collection process → outbound transfer → transfer volume.

Metrics: files read, bytes read, files transferred, bytes transferred, time to detection, bytes transferred before containment.

### Fidelity

- SMB collection: reproduced
- Transfer mechanism: reproduced
- Cloud destination: not used (internal destination)
- Transfer fidelity: partial — cloud-storage exfiltration not reproduced

### Limitations

The transfer destination is internal. Real cloud-storage exfiltration telemetry (DNS to cloud providers, TLS to external IPs) is not generated.

---

## 9. RDP and Secondary Remote Access

### Historical Evidence

C0015 operators used RDP and AnyDesk for remote interactive access during the intrusion.

**Evidence classification:** OBSERVED (RDP/AnyDesk documented in C0015)

### Lab Implementation

Real RDP sessions between lab systems, capturing:

- Session creation and disconnection
- Remote interactive logon events
- Process activity during the RDP session

AnyDesk-related behavior will be handled through historical evidence documentation or an internal equivalent rather than relying on public relay infrastructure.

### Expected Telemetry

- Windows Security logon Type 10 (RemoteInteractive)
- RDP connection events (Event IDs 4624, 4778, 4779)
- Sysmon process creation within the RDP session
- Network connections on TCP/3389

### Detection Objective

Distinguish: ordinary network logon vs. remote interactive logon vs. legitimate administration vs. remote access embedded in a prior intrusion chain.

### Fidelity

- RDP mechanism: reproduced
- AnyDesk: documented only, not executed in lab

### Limitations

AnyDesk relay infrastructure is not reproduced. Detection of third-party remote access tools requires different network indicators than what this experiment generates.

---

## 10. Conti Impact Reconstruction

### Historical Evidence

Conti ransomware was deployed as the final impact stage of C0015, encrypting files across local and network locations.

**Evidence classification:** OBSERVED (Conti deployment documented in C0015)

### Lab Implementation

The original Conti binary is not used. A bounded impact simulator operates against a disposable pre-generated corpus with a manifest.

Hard boundaries enforced by the simulator:

- Exact allowlisted root directory
- Lab marker file requirement
- Maximum file count
- Maximum byte count
- Maximum execution time
- No drive root or Windows/system directories
- No arbitrary UNC targets
- No reparse/symlink escape
- No SYSTEM execution
- No self-propagation

```text
enumerate dummy files → high-rate controlled file transformations
  → rename / extension changes → optional bounded replacement/delete
  → note creation → local impact run → separate SMB impact run
```

### Expected Telemetry

- High-rate file modification events
- File rename/extension change events
- Note creation across directories
- SMB write activity on FS01
- Process and account context for all activity

### Detection Objective

Detect behavioral invariants: modification breadth, modification rate, affected directory count, local vs. SMB scope, account/process context, repeated note creation, unusual fan-out.

Legitimate controls for comparison: backup, archive extraction, software build output, synchronization, administrative bulk file operations.

### Fidelity

- Historical role: Conti ransomware impact — preserved
- File transformation behaviors: reproduced with safe operations
- Encryption: not performed (behavioral invariants preserved without actual cryptographic destruction)
- Self-propagation: not reproduced

### Limitations

The simulator does not perform real encryption. Detection relying on entropy analysis or cryptographic signatures will not be validated. The bounded scope may not reproduce the full filesystem fan-out of an actual ransomware deployment.

---

## 11. Containment and Recovery

### Historical Evidence

Containment and recovery are operational responses to the C0015 intrusion chain.

### Lab Implementation

**Prevention tests:**
- Office protection, LOLBin restrictions, least privilege
- WMI policy, RDP policy, SMB segmentation
- Endpoint hardening controls

**Containment actions:**
- Terminate controlled process
- Disable/revoke lab account
- Block SMB access
- Block relevant network flow
- Isolate endpoint (when supported)

**Timeline metrics:**

```text
behavior start → event generated → event ingested
  → atomic detection → correlation → analyst action → containment effective
```

**Recovery:**
Restore impact corpus from protected backup and verify: file count, hashes, ACLs, recovery time. VM snapshots are used only for lab reset, not as the enterprise recovery model.

### Detection Objective

Measure: time from behavior to containment, bytes/files affected before containment, recovery completeness and speed.

### Fidelity

Containment and recovery mechanisms are real lab operations, not simulations.

### Limitations

Enterprise-grade containment (EDR isolation, SOAR playbooks, network ACL automation) depends on available lab tooling and license features.

---

## Telemetry Validation Strategy

Each behavior is validated in layers before detection logic is written:

1. Execute the safe behavior on the relevant endpoint.
2. Confirm the expected Windows/Sysmon event locally.
3. Confirm Elastic ingestion and ECS field mapping.
4. Prototype KQL/EQL/ES|QL logic.
5. Evaluate false positives and temporal constraints.
6. Promote validated logic into an atomic or correlation detection.

**Phase gate:** If telemetry is missing, the sensor is fixed before detection logic is written.

## Safety Notes

No real ransomware, Bazar, or Conti payload is used. The documentation describes the historical original behavior accurately even when the live implementation is a safe substitute.

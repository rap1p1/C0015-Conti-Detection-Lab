# Attack Emulation

## Overview

This document defines the C0015 intrusion lifecycle reconstruction. Each section corresponds to a stage of the documented campaign, not to isolated ATT&CK technique exercises.

The lab does not execute original Bazar, Cobalt Strike, or Conti binaries. Each stage is reconstructed with controlled surrogates that preserve the historical role, Windows/network mechanisms, and causal relationships of the original campaign.

---

## 1. Initial Execution / Bootstrap

**Phase 1 status:** PASS

### Historical Evidence

C0015 began with user execution of a document or script that triggered an HTA/script-based bootstrap chain. This chain wrote artifacts to user-writable locations and loaded a DLL through proxy execution mechanisms, leading into the Bazar stage.

**Evidence classification:** OBSERVED (document execution → DLL loading chain documented in campaign reports)

### Lab Implementation — SAFE SUBSTITUTE

This is a benign Bazar-stage reconstruction. No real Bazar malware was executed. The bootstrap chain uses a controlled document, benign HTA, benign DLL, and a marker-file execution proof — preserving process relationships, user context, file-path class, and DLL load mechanism while substituting all malicious payloads with safe equivalents.

**Lab execution note:** The macro in `test.docm` was manually triggered during controlled testing. This is not a realistic victim interaction. Historical C0015 delivery relied on social-engineering-driven macro execution; the controlled lab trigger must not be conflated with that.

#### Observed causal chain

```text
explorer.exe
  │
  ▼
WINWORD.EXE (test.docm)                             [OBSERVED — Sysmon EID 1]
  │
  ▼
cmd.exe                                               [OBSERVED — Sysmon EID 1]
  │   PID 5564, Parent PID 2288 (WINWORD.EXE)
  │   cmd.exe /c "C:\Windows\System32\mshta.exe C:\Users\Public\C0015\bootstrap.hta"
  │
  ▼
mshta.exe                                             [OBSERVED — Sysmon EID 1]
  │   PID 6592, Parent PID 5564 (cmd.exe)
  │
  ├──▶ HTTP retrieval from 192.168.50.100:8000        [OBSERVED — server-side HTTP 200]
  │       │                                           [INFERRED — EID 3 PID correlation]
  │       ├──▶ benign.txt / downloaded-marker.txt     [OBSERVED — Sysmon EID 11]
  │       └──▶ c0015-marker.dll                       [OBSERVED — Sysmon EID 11]
  │
  ▼
regsvr32.exe                                          [OBSERVED — Sysmon EID 1]
  │   PID 5872, Parent PID 3604 (mshta.exe)
  │   regsvr32.exe /s "C:\Users\Public\C0015\c0015-marker.dll"
  │
  ├──▶ ImageLoad: c0015-marker.dll                    [OBSERVED — Sysmon EID 7]
  │       SHA-256: d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544
  │       Signed: false
  │
  ▼
DllRegisterServer() executes                          [OBSERVED — marker file creation]
  │
  ▼
dll-executed.txt created                              [OBSERVED — Sysmon EID 11]
```

#### Lab endpoints

| Host | Role | Address |
|---|---|---|
| WS01 | Victim workstation | 192.168.50.20 |
| Kali | HTTP server (TCP/8000) | 192.168.50.100 |

### Phase 1 Checkpoints

#### P1-A — Office → cmd → mshta (PASS)

OBSERVED:
- WINWORD.EXE spawned cmd.exe (PID 5564, parent PID 2288).
- cmd.exe spawned mshta.exe (PID 6592, parent PID 5564).

Telemetry source: Sysmon Event ID 1 on WS01.

#### P1-B — Benign network retrieval (PASS)

OBSERVED:
- PID 6032 opened an outbound TCP connection to 192.168.50.100:8000 (Sysmon Event ID 3, 2026-09-19T01:23:48.766Z).
- Kali independently recorded a successful `GET /benign.txt` → HTTP 200 from 192.168.50.20.
- PID 6032 was identified as `mshta.exe` in the subsequent FileCreate event (Sysmon Event ID 11, 2026-09-19T01:23:52.680Z).
- mshta.exe created `C:\Users\Public\C0015\downloaded-marker.txt`.

INFERRED / CORRELATED:
The Event ID 3 network connection belongs to the same mshta.exe execution based on matching PID, close temporal proximity, server-side HTTP evidence, and subsequent file creation. Event ID 3 itself contained `Image=<unknown process>` and a null ProcessGuid — it did **not** directly identify the process as mshta.exe.

#### P1-C — Benign DLL + regsvr32 execution (PASS)

OBSERVED:
- mshta.exe (PID 3604, entity_id `{88E52A21-F5AB-6AAD-CF01-000000001500}`) created `C:\Users\Public\C0015\c0015-marker.dll` (Sysmon Event ID 11).
- mshta.exe spawned regsvr32.exe (PID 5872, entity_id `{88E52A21-F5AB-6AAD-D001-000000001500}`, 2026-09-19T02:38:35.452Z) with command line `regsvr32.exe /s "C:\Users\Public\C0015\c0015-marker.dll"`.
- regsvr32.exe loaded `c0015-marker.dll` (Sysmon Event ID 7, 2026-09-19T02:38:35.469Z). SHA-256: `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544`. The loaded DLL hash on WS01 matches the artifact hash calculated on Kali before delivery.
- regsvr32.exe created `C:\Users\Public\C0015\dll-executed.txt` (Sysmon Event ID 11) as a consequence of the benign DLL's `DllRegisterServer()` implementation.
- Kali independently recorded a successful `GET /c0015-marker.dll` → HTTP 200 from 192.168.50.20.
- User: `C0015\duc.user`, Integrity: Medium.

NOT OBSERVED / SENSOR GAP:
No corresponding Sysmon Event ID 3 was found on WS01 for the final P1-C DLL retrieval. This does not invalidate P1-C because the remainder of the causal chain is independently supported by server-side HTTP evidence, FileCreate, ProcessCreate, ImageLoad, and the DLL execution marker.

### Timing Limitation

Windows/Sysmon UTC events for the P1-C execution cluster around 2026-09-19 02:38 UTC. The Kali Python HTTP server displayed approximately 18/Sep/2026 22:38. Cross-host timestamps are **not** precisely synchronized due to known Kali clock skew. Do not normalize or invent a corrected Kali timestamp.

### Fidelity

- Parent/child relationships: preserved
- User context: preserved
- File-path class: preserved (user-writable `C:\Users\Public\C0015\`)
- DLL load mechanism: preserved (regsvr32 silent registration)
- DLL hash continuity: verified (Kali → WS01)
- Actual malware payload: **not used** — this is a SAFE SUBSTITUTE

### Limitations

- The bootstrap artifacts are benign. The DLL contains no malicious functionality. Detection must rely on behavioral relationships rather than payload signatures.
- The macro was triggered manually, not through social engineering.
- `CreationUtcTime` and event `@timestamp` may differ for files downloaded/overwritten during repeated controlled testing. Do not use `CreationUtcTime` alone as the authoritative execution timestamp.
- No Sysmon Event ID 3 captured for the P1-C DLL network transfer (sensor gap).
- Kali clock skew prevents precise cross-host timeline correlation.

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

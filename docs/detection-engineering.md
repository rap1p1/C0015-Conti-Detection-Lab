# Detection Engineering

## Detection Architecture

The project builds detections in three layers:

```text
Atomic analytics (low-confidence building blocks)
    ↓
Behavioral correlations (cross-host, multi-signal)
    ↓
Campaign-level investigation (full chain reconstruction)
```

Atomic detections are intentionally broad to preserve recall within bounded behavior families. Correlation rules combine multiple atomic signals to increase confidence and reduce noise. Campaign-level investigation ties correlations into the C0015 intrusion narrative.

---

## Atomic Building Blocks

Existing validated atomic detections:

| Rule | ATT&CK | Severity | Risk | Status |
|---|---|---:|---:|---|
| Windows Process Discovery via Tasklist | T1057 | Low | 15 | DETECTED |
| Domain Groups Discovery via Net | T1069.002 | Low | 20 | DETECTED |
| Domain Trust Discovery via NLTest | T1482 | Low | 20 | DETECTED |
| Network Share Discovery via Net View | T1135 | Low | 20 | DETECTED |
| Remote SMB File Read from Network Share | T1039 | Low | 25 | DETECTED |

Atomic rules have no notification actions. Their purpose is to create reusable signals for correlation and investigation.

### T1057 — Process Discovery

```kql
event.type : "start"
and process.name : "tasklist.exe"
```

Intentionally broad. `tasklist.exe` is common administrative activity and is not malicious by itself.

### T1069.002 — Account/Group Discovery

```kql
event.type : "start"
and process.name : ("net.exe" or "net1.exe")
and (
  process.command_line : *group*
  or process.command_line : *user*
  or process.command_line : *localgroup*
)
```

Covers both `net.exe` and `net1.exe`. The lab observed `cmd.exe → net.exe → net1.exe`, but the analytic does not require that specific chain. Broader than only `Domain Admins` so correlation provides precision.

### T1482 — Domain Trust Discovery

```kql
event.type : "start"
and process.name : "nltest.exe"
and (
  process.command_line : *domain_trusts*
  or process.command_line : *all_trusts*
  or process.command_line : *trusted_domains*
)
```

### T1135 — Network Share Discovery

```kql
event.type : "start"
and process.name : ("net.exe" or "net1.exe")
and process.command_line : *view*
```

### T1039 — Remote SMB File Access

```kql
event.code : "5145"
and event.outcome : "success"
and event.type : "access"
and file.name : *
and source.ip : *
```

Uses FS01 server-side auditing (Event ID 5145). Stronger evidence of actual remote file access than a client-side shell command alone.

### Duplicate Handling

One action can produce multiple atomic alerts. The lab observed duplicate `net.exe`/`net1.exe` signals and multiple 5145 events for a single SMB read. Correlation counts distinct behavior families rather than raw alert count, preserving recall at the atomic layer while preventing duplicates from inflating confidence.

---

## Validated Correlations

### C1 — Discovery to SMB Collection

**Rule:** `Suspicious Discovery and Network Share Collection Chain`
**Severity:** Medium
**Risk score:** 60
**Status:** DETECTED — end-to-end validation PASS

The ES|QL rule reads alerts from the five atomic rules, maps each to a behavior family, and aggregates by `user.name`.

Required conditions:

- At least four distinct behavior families
- At least one network-share collection signal
- Activity across at least two hosts
- At least one source IP in contributing alerts
- The newest contributing signal must be recent enough for the active correlation window

The production schedule runs every five minutes with a fifteen-minute look-back. Validation intervals were temporarily reduced to one minute during testing.

ATT&CK mapping: T1057, T1069.002, T1482, T1135, T1039

---

## Phase 1 Detection Hypotheses

The following analytic opportunities are supported by Phase 1 live telemetry evidence. These are detection hypotheses, **not** production rules. Each requires further validation, tuning, and false-positive analysis before promotion.

### DH-01: Office Application Spawning cmd.exe

**Behavior:** WINWORD.EXE → cmd.exe child process.

**Required telemetry:** Sysmon Event ID 1 with parent-child relationship.

**KQL sketch:**

```kql
event.code:"1" and
process.name:"cmd.exe" and
process.parent.name:("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE")
```

**False-positive considerations:**
- Legitimate Office add-ins or automation may spawn cmd.exe.
- Some enterprise document workflows use macro-driven shell commands.
- Must distinguish controlled lab trigger from social-engineering delivery context.

**Phase 1 evidence:** OBSERVED — WINWORD.EXE (PID 2288) → cmd.exe (PID 5564).

### DH-02: cmd.exe → mshta.exe

**Behavior:** cmd.exe launching mshta.exe, particularly with an HTA file argument.

**Required telemetry:** Sysmon Event ID 1 with command-line arguments.

**KQL sketch:**

```kql
event.code:"1" and
process.name:"mshta.exe" and
process.parent.name:"cmd.exe"
```

**False-positive considerations:**
- Rare in enterprise environments, but legitimate HTA-based admin tools exist.
- Low expected false-positive rate in most environments.

**Phase 1 evidence:** OBSERVED — cmd.exe (PID 5564) → mshta.exe (PID 6592) with HTA argument.

### DH-03: mshta.exe Spawning regsvr32.exe

**Behavior:** mshta.exe launching regsvr32.exe, indicating proxy execution chaining.

**Required telemetry:** Sysmon Event ID 1 with parent-child relationship and command-line arguments.

**KQL sketch:**

```kql
event.code:"1" and
process.name:"regsvr32.exe" and
process.parent.name:"mshta.exe"
```

**False-positive considerations:**
- Very rare in legitimate workflows. mshta.exe is not a typical parent for regsvr32.exe.
- High signal-to-noise expected.

**Phase 1 evidence:** OBSERVED — mshta.exe (PID 3604, entity_id `{88E52A21-F5AB-6AAD-CF01-000000001500}`) → regsvr32.exe (PID 5872, entity_id `{88E52A21-F5AB-6AAD-D001-000000001500}`).

### DH-04: regsvr32 Loading Unsigned DLL from User-Writable Path

**Behavior:** regsvr32.exe loading an unsigned DLL from a user-writable or public directory.

**Required telemetry:** Sysmon Event ID 7 (ImageLoad) with signature status and file path.

**KQL sketch:**

```kql
event.code:"7" and
process.name:"regsvr32.exe" and
file.path:("C:\\Users\\Public\\*" or "C:\\Users\\*\\AppData\\*" or "C:\\ProgramData\\*" or "C:\\Temp\\*") and
file.code_signature.signed:false
```

**False-positive considerations:**
- Legitimate software installers may use regsvr32 with unsigned DLLs during installation.
- Path-based filtering requires tuning for the environment.
- Hash-based allowlisting can reduce false positives for known legitimate DLLs.

**Phase 1 evidence:** OBSERVED — regsvr32.exe loaded `C:\Users\Public\C0015\c0015-marker.dll` (unsigned, SHA-256 `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544`).

### DH-05: Bootstrap Chain Correlation (Process + File + ImageLoad)

**Behavior:** Correlated sequence: Office app → cmd.exe → mshta.exe → file creation in user-writable path → regsvr32.exe → ImageLoad of unsigned DLL → execution marker.

**Required telemetry:** Sysmon Event IDs 1, 7, 11 with entity_id/ProcessGuid for reliable cross-event correlation.

**Design note:** This is a candidate for the C2 correlation rule (see Correlation Roadmap). It requires multi-event correlation using process ancestry, not individual atomic signals.

**False-positive considerations:**
- The full chain is highly specific; false-positive rate is expected to be very low.
- Individual components (DH-01 through DH-04) are more prone to false positives in isolation.

**Phase 1 evidence:** Full chain OBSERVED across Sysmon EID 1, 7, and 11.

### DH-06: Network Visibility Limitation (Event ID 3 Gap)

**Observation:** The P1-C DLL retrieval was not captured by Sysmon Event ID 3 despite server-side HTTP evidence confirming the transfer occurred.

**Detection implication:** Analytics that depend solely on Sysmon Event ID 3 for network transfer detection may miss real activity. Detection strategies should incorporate multiple telemetry sources:

- Sysmon Event ID 3 (when available)
- Sysmon Event ID 11 (FileCreate as downstream evidence)
- Sysmon Event ID 7 (ImageLoad with hash verification)
- Server-side/proxy/firewall logs (independent network evidence)

**Required action:** Investigate why Event ID 3 was not generated for the P1-C transfer. Possible causes include Sysmon configuration filtering, event volume limits, or timing.



---

## Correlation Roadmap

### C2 — Bootstrap / Foothold

```text
document/script → proxy execution or DLL → unusual network activity
```

Correlates the initial execution chain from the Bazar stage reconstruction with outbound callback activity.

### C3 — Identity / WMI Pivot

```text
source host → privileged authentication → WMI remote execution
  → target process → new callback
```

Correlates the authentication and lateral-movement evidence from the WMI phase across WS01 and FS01.

### C4 — Collection / Transfer

```text
SMB access → collecting process → outbound transfer
```

Correlates file-share access with data staging and transfer activity.

### C5 — Injection Suspicion

```text
source process → target process access → module/target behavior
```

Correlates process access events with module loading and behavioral changes in the target process.

### C6 — Impact

```text
process/account → high-rate file activity → broad local/SMB scope
```

Correlates the behavioral invariants of the Conti impact reconstruction: modification rate, breadth, and scope.

---

## Detection Engineering Loop

Every experiment follows the same workflow:

```text
1.  Define the detection hypothesis
2.  Record lab state and configuration
3.  Run a legitimate control
4.  Run the target behavior
5.  Validate local telemetry
6.  Validate Elastic ingestion and field mapping
7.  Let the scheduled analytic execute
8.  Record the result
9.  Change one meaningful observable (controlled variation)
10. Re-run the experiment
11. Improve the analytic if it misses
12. Re-run target and control cases (regression)
13. Close the experiment with evidence
```

### Result States

| State | Meaning |
|---|---|
| NOT RUN | Experiment not yet executed |
| BLOCKED BY ENVIRONMENT | Infrastructure prerequisite not met |
| PREVENTED | Security control stopped the behavior |
| SENSOR GAP | Expected telemetry not generated |
| INGEST/MAPPING GAP | Telemetry generated but not correctly ingested or mapped |
| DETECTION MISS | Telemetry available but analytic did not fire |
| DETECTED | Analytic correctly identified the behavior |
| PARTIAL | Detection fired but with incomplete coverage |

---

## Noise Controls

Atomic alerts are expected to be noisy. The correlation layer reduces noise through:

- Aggregation by user identity
- Required collection activity (not just discovery)
- Multi-host context requirement
- Bounded look-back window
- Freshness condition on the latest contributing signal

Native alert suppression was not available under the current license; duplicate correlation alerts are controlled at the query and schedule layer.

---

## EQL Validation Queries

Entity-aware EQL sequences are used for telemetry validation of parent-child process relationships. These are development/validation tools, not production detections.

Available EQL prototypes:

| File | Purpose |
|---|---|
| `t1057-cmd-tasklist-sequence.eql` | cmd.exe → tasklist.exe parent-child validation |
| `t1059-003-cmd-whoami-sequence.eql` | cmd.exe → whoami.exe parent-child validation |
| `t1069-002-cmd-net-domain-groups.eql` | cmd.exe → net.exe domain group discovery validation |
| `t1135-cmd-net-view-sequence.eql` | cmd.exe → net.exe share discovery validation |
| `t1482-cmd-nltest-sequence.eql` | cmd.exe → nltest.exe trust discovery validation |

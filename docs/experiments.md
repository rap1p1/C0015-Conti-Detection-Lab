# Experiments

## Experiment Ledger

This document tracks all experiments conducted in the C0015 Conti Detection Lab. Each experiment follows the standardized template below.

### Template

```text
Experiment ID:        [unique identifier]
Historical hypothesis: [what C0015 evidence this tests]
ATT&CK mapping:       [technique ID and name]
C0015 recorded:        [YES / NO]
Lab implementation:    [exact commands or process]
Expected telemetry:    [event IDs, fields, sources]
Legitimate control:    [benign equivalent for comparison]
Target run:            [attack emulation execution]
Variation:             [controlled change to test detection robustness]
Result:                [NOT RUN | BLOCKED BY ENVIRONMENT | PREVENTED |
                        SENSOR GAP | INGEST/MAPPING GAP | DETECTION MISS |
                        DETECTED | PARTIAL]
Detection status:      [rule name and current state]
Fidelity:              [what was preserved vs. changed]
Evidence:              [specific events, timestamps, alert references]
Limitations:           [known gaps or constraints]
```

---

## EXP-001: Process Discovery via Tasklist

| Field | Value |
|---|---|
| **Experiment ID** | EXP-001 |
| **Historical hypothesis** | C0015 operators used `tasklist` for process enumeration on the victim workstation |
| **ATT&CK mapping** | T1057 Process Discovery |
| **C0015 recorded** | YES |
| **Lab implementation** | `tasklist` executed in `cmd.exe` on WS01 as `duc.user` |
| **Expected telemetry** | Sysmon Event ID 1 — `tasklist.exe` process creation |
| **Legitimate control** | Normal administrative `tasklist` usage |
| **Target run** | Executed as part of discovery chain |
| **Variation** | Tested with long-running `cmd.exe` session (maxspan constraint) |
| **Result** | DETECTED |
| **Detection status** | `Windows Process Discovery via Tasklist` — active |
| **Fidelity** | Exact command reproduced |
| **Evidence** | Sysmon Process Create event ingested; atomic KQL rule fired |
| **Limitations** | `tasklist.exe` is common administrative activity; atomic detection alone has high false-positive rate |

---

## EXP-002: Domain Groups Discovery via Net

| Field | Value |
|---|---|
| **Experiment ID** | EXP-002 |
| **Historical hypothesis** | C0015 operators used `net group "Domain Admins" /domain` for group enumeration |
| **ATT&CK mapping** | T1069.002 Domain Groups Discovery |
| **C0015 recorded** | YES |
| **Lab implementation** | `net group "Domain Admins" /domain` on WS01 as `duc.user` |
| **Expected telemetry** | Sysmon Event ID 1 — `net.exe` and `net1.exe` process creation |
| **Legitimate control** | Normal administrative group enumeration |
| **Target run** | Executed as part of discovery chain |
| **Variation** | Observed `cmd.exe → net.exe → net1.exe` child-process chain |
| **Result** | DETECTED |
| **Detection status** | `Domain Groups Discovery via Net` — active |
| **Fidelity** | Exact command reproduced |
| **Evidence** | Both `net.exe` and `net1.exe` events ingested; duplicate signals handled by correlation |
| **Limitations** | Produces duplicate atomic alerts due to `net.exe`/`net1.exe` chain |

---

## EXP-003: Domain Trust Discovery via NLTest

| Field | Value |
|---|---|
| **Experiment ID** | EXP-003 |
| **Historical hypothesis** | C0015 operators used `nltest /domain_trusts /all_trusts` for trust enumeration |
| **ATT&CK mapping** | T1482 Domain Trust Discovery |
| **C0015 recorded** | YES |
| **Lab implementation** | `nltest /domain_trusts /all_trusts` on WS01 as `duc.user` |
| **Expected telemetry** | Sysmon Event ID 1 — `nltest.exe` process creation |
| **Legitimate control** | Normal administrative trust validation |
| **Target run** | Executed as part of discovery chain |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | `Domain Trust Discovery via NLTest` — active |
| **Fidelity** | Exact command reproduced |
| **Evidence** | Sysmon Process Create event ingested; atomic KQL rule fired |
| **Limitations** | Single-domain lab limits the richness of trust enumeration output |

---

## EXP-004: Network Share Discovery via Net View

| Field | Value |
|---|---|
| **Experiment ID** | EXP-004 |
| **Historical hypothesis** | C0015 operators used `net view` to discover available network shares |
| **ATT&CK mapping** | T1135 Network Share Discovery |
| **C0015 recorded** | YES |
| **Lab implementation** | `net view \\FS01` on WS01 as `duc.user` |
| **Expected telemetry** | Sysmon Event ID 1 — `net.exe` process creation with `view` argument |
| **Legitimate control** | Normal administrative share enumeration |
| **Target run** | Executed as part of discovery chain |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | `Network Share Discovery via Net View` — active |
| **Fidelity** | Exact command reproduced |
| **Evidence** | Sysmon Process Create event ingested; atomic KQL rule fired |
| **Limitations** | Lab has limited share topology compared to a real enterprise |

---

## EXP-005: Remote SMB File Read

| Field | Value |
|---|---|
| **Experiment ID** | EXP-005 |
| **Historical hypothesis** | C0015 operators accessed files on network shares for data collection |
| **ATT&CK mapping** | T1039 Data from Network Shared Drive |
| **C0015 recorded** | YES |
| **Lab implementation** | `type \\FS01\Finance\budget-q3.txt` on WS01 as `duc.user` |
| **Expected telemetry** | Windows Security Event ID 5145 on FS01 — remote file access |
| **Legitimate control** | Normal user file access on authorized shares |
| **Target run** | Executed as part of discovery-to-collection chain |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | `Remote SMB File Read from Network Share` — active |
| **Fidelity** | SMB access mechanism reproduced; server-side evidence captured |
| **Evidence** | 5145 event: `user.name=duc.user`, `source.ip=192.168.50.20`, `file.name=budget-q3.txt`, `ReadData` access |
| **Limitations** | `type` is an internal `cmd.exe` command — no separate `type.exe` process creation event |

---

## EXP-006: EQL Parent-Child Correlation

| Field | Value |
|---|---|
| **Experiment ID** | EXP-006 |
| **Historical hypothesis** | Process ancestry is a reliable correlation key for campaign reconstruction |
| **ATT&CK mapping** | N/A (methodology experiment) |
| **C0015 recorded** | N/A |
| **Lab implementation** | EQL sequence queries using `process.entity_id` / `process.parent.entity_id` |
| **Expected telemetry** | Sysmon Event ID 1 with entity ID fields |
| **Legitimate control** | Normal parent-child process relationships |
| **Target run** | cmd.exe → tasklist.exe, cmd.exe → net.exe sequences |
| **Variation** | Long-running cmd.exe session exceeded `maxspan` — reopened shell to match |
| **Result** | DETECTED |
| **Detection status** | EQL prototypes validated; used as development tools |
| **Fidelity** | N/A (methodology) |
| **Evidence** | Entity-aware EQL matched correctly; PID-based correlation confirmed unreliable |
| **Limitations** | `maxspan` is a real temporal constraint — long-lived parent processes may fall outside the window |

---

## EXP-007: VMware False-Positive Analysis

| Field | Value |
|---|---|
| **Experiment ID** | EXP-007 |
| **Historical hypothesis** | Lab infrastructure may generate false-positive telemetry |
| **ATT&CK mapping** | N/A (noise analysis) |
| **C0015 recorded** | N/A |
| **Lab implementation** | Observed `vmtoolsd.exe → cmd.exe` chains during VM power-on/resume |
| **Expected telemetry** | Sysmon Event ID 1 — benign cmd.exe from VMware Tools |
| **Legitimate control** | VMware Tools lifecycle scripts are expected behavior |
| **Target run** | N/A (observed during normal lab operations) |
| **Variation** | N/A |
| **Result** | DETECTED (false positive identified) |
| **Detection status** | Narrow Sysmon exclusion added for VMware Tools lifecycle pattern |
| **Fidelity** | N/A (noise analysis) |
| **Evidence** | `vmtoolsd.exe` parent with `poweron-vm-default.bat` / `resume-vm-default.bat` arguments |
| **Limitations** | Only the specific VMware Tools pattern is excluded; other `vmtoolsd.exe → cmd.exe` chains remain visible |

---

## EXP-008: Building-Block Duplication Analysis

| Field | Value |
|---|---|
| **Experiment ID** | EXP-008 |
| **Historical hypothesis** | A single action may produce multiple atomic alerts, requiring deduplication at the correlation layer |
| **ATT&CK mapping** | N/A (methodology experiment) |
| **C0015 recorded** | N/A |
| **Lab implementation** | Single `net group "Domain Admins" /domain` produced multiple `net.exe`/`net1.exe` alerts; single SMB read produced multiple 5145 alerts |
| **Expected telemetry** | Multiple atomic alerts from a single action |
| **Legitimate control** | N/A |
| **Target run** | Discovery chain replay |
| **Variation** | N/A |
| **Result** | DETECTED (duplication confirmed) |
| **Detection status** | Correlation uses `COUNT_DISTINCT` behavior families instead of raw alert count |
| **Fidelity** | N/A (methodology) |
| **Evidence** | Multiple atomic alerts per action observed; correlation correctly deduplicated |
| **Limitations** | Behavior-family deduplication may mask genuinely distinct instances of the same technique |

---

## EXP-009: Cross-Host Correlation Validation

| Field | Value |
|---|---|
| **Experiment ID** | EXP-009 |
| **Historical hypothesis** | Discovery followed by SMB collection across hosts indicates coordinated reconnaissance-to-collection activity |
| **ATT&CK mapping** | T1057, T1069.002, T1482, T1135, T1039 |
| **C0015 recorded** | YES |
| **Lab implementation** | Full discovery chain on WS01 followed by SMB file access on FS01, all as `duc.user` |
| **Expected telemetry** | Five atomic alerts plus one ES\|QL correlation alert |
| **Legitimate control** | Individual discovery commands in isolation (no correlation fire) |
| **Target run** | Complete chain replayed within a short window |
| **Variation** | Rule intervals temporarily reduced to one minute for faster validation |
| **Result** | DETECTED |
| **Detection status** | `Suspicious Discovery and Network Share Collection Chain` — active, Medium severity, risk score 60 |
| **Fidelity** | Discovery and collection mechanisms reproduced with documented C0015 procedures |
| **Evidence** | One Medium Elastic Security alert generated after five atomic behavior families fired |
| **Limitations** | Correlation does not yet mathematically join FS01 `source.ip` back to exact WS01 host identity |

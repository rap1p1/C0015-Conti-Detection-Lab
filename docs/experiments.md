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

---

## EXP-010: Office → cmd → mshta Bootstrap Chain (P1-A)

| Field | Value |
|---|---|
| **Experiment ID** | EXP-010 |
| **Historical hypothesis** | C0015 initial execution involved a document triggering an HTA/script-based bootstrap chain through proxy execution |
| **ATT&CK mapping** | User Execution surrogate context; mshta proxy execution behavior |
| **C0015 recorded** | YES (structural fidelity — benign surrogate, not exact malware) |
| **Lab implementation** | `test.docm` macro → `cmd.exe /c mshta.exe C:\Users\Public\C0015\bootstrap.hta` on WS01 as `duc.user`. Macro was manually triggered — not a realistic victim interaction. |
| **Expected telemetry** | Sysmon Event ID 1 — WINWORD.EXE → cmd.exe → mshta.exe process chain |
| **Legitimate control** | Normal document open without macro execution |
| **Target run** | Controlled macro trigger on WS01 |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | Telemetry validated — detection hypothesis documented (no production rule yet) |
| **Fidelity** | Parent/child relationships and user context preserved; benign SAFE SUBSTITUTE, not real Bazar execution |
| **Evidence** | Sysmon EID 1: cmd.exe PID 5564 (parent WINWORD.EXE PID 2288); mshta.exe PID 6592 (parent cmd.exe PID 5564) |
| **Limitations** | Macro was manually triggered (Alt+F8); does not replicate social-engineering delivery |

---

## EXP-011: Benign Network Retrieval via mshta (P1-B)

| Field | Value |
|---|---|
| **Experiment ID** | EXP-011 |
| **Historical hypothesis** | The bootstrap chain retrieved artifacts from a remote server over HTTP |
| **ATT&CK mapping** | N/A (network retrieval behavior — structural fidelity only) |
| **C0015 recorded** | YES (structural fidelity — benign surrogate) |
| **Lab implementation** | mshta.exe on WS01 retrieved `benign.txt` from Kali HTTP server at 192.168.50.100:8000 |
| **Expected telemetry** | Sysmon Event ID 3 (network connection), Event ID 11 (file creation), server-side HTTP log |
| **Legitimate control** | N/A |
| **Target run** | HTA-triggered HTTP download during bootstrap chain |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | Telemetry validated — detection hypothesis documented (no production rule yet) |
| **Fidelity** | Network retrieval mechanism preserved; artifact is benign text, not malware payload |
| **Evidence** | Sysmon EID 3: PID 6032 → 192.168.50.100:8000 (2026-09-19T01:23:48.766Z), Image=`<unknown process>`, ProcessGuid=null. Sysmon EID 11: PID 6032 (mshta.exe) created `downloaded-marker.txt` (2026-09-19T01:23:52.680Z). Kali HTTP log: `GET /benign.txt` → HTTP 200 from 192.168.50.20. |
| **Limitations** | Event ID 3 contained `Image=<unknown process>` — process attribution to mshta.exe is INFERRED from PID correlation, temporal proximity, server-side evidence, and subsequent FileCreate. This is not direct sensor identification. |

---

## EXP-012: Benign DLL Delivery and regsvr32 Execution (P1-C)

| Field | Value |
|---|---|
| **Experiment ID** | EXP-012 |
| **Historical hypothesis** | The bootstrap chain delivered a DLL and executed it via regsvr32 proxy execution |
| **ATT&CK mapping** | regsvr32 proxy execution behavior |
| **C0015 recorded** | YES (structural fidelity — benign surrogate, not exact Bazar DLL) |
| **Lab implementation** | mshta.exe wrote `c0015-marker.dll` to `C:\Users\Public\C0015\`, then spawned `regsvr32.exe /s "C:\Users\Public\C0015\c0015-marker.dll"` on WS01 as `duc.user` |
| **Expected telemetry** | Sysmon EID 1 (regsvr32 ProcessCreate), EID 7 (ImageLoad with hash), EID 11 (FileCreate for DLL and execution marker), EID 3 (network connection for DLL retrieval) |
| **Legitimate control** | Normal regsvr32 COM registration of signed DLLs in system paths |
| **Target run** | Controlled bootstrap chain on WS01 |
| **Variation** | None yet |
| **Result** | DETECTED |
| **Detection status** | Telemetry validated — detection hypothesis documented (no production rule yet) |
| **Fidelity** | DLL load mechanism and process chain preserved; DLL is benign SAFE SUBSTITUTE with marker-file proof of execution |
| **Evidence** | Sysmon EID 11: mshta.exe (PID 3604, entity_id `{88E52A21-F5AB-6AAD-CF01-000000001500}`) created `c0015-marker.dll`. Sysmon EID 1: regsvr32.exe PID 5872 (entity_id `{88E52A21-F5AB-6AAD-D001-000000001500}`, parent mshta.exe PID 3604, 2026-09-19T02:38:35.452Z). Sysmon EID 7: regsvr32.exe loaded `c0015-marker.dll` SHA-256 `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544` (unsigned, 2026-09-19T02:38:35.469Z). Sysmon EID 11: regsvr32.exe created `dll-executed.txt`. Kali HTTP: `GET /c0015-marker.dll` → HTTP 200 from 192.168.50.20. |
| **Limitations** | No Sysmon Event ID 3 found on WS01 for the P1-C DLL retrieval (SENSOR GAP — server-side evidence proves transfer occurred). `CreationUtcTime` and `@timestamp` may diverge for files overwritten during repeated testing. Kali clock skew prevents precise cross-host timestamp correlation. |


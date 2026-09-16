# Attack Emulation

## Scope

This project reproduces selected behaviors documented for MITRE ATT&CK campaign C0015 using native Windows utilities and benign data. The purpose is to validate telemetry and detections, not to reproduce malware payloads.

## Emulation model

Each behavior is classified as one of:
- **Emulated** - real Windows mechanism with benign target/data.
- **Simulated** - observable behavior recreated without unsafe payloads.
- **Documented only** - technique is studied but not executed.

## Completed behaviors

| ATT&CK | Technique | Lab action | Result |
|---|---|---|---|
| T1059.003 | Windows Command Shell | Interactive `cmd.exe` activity | PASS |
| T1057 | Process Discovery | `tasklist` | PASS |
| T1069.002 | Domain Groups | `net group ... /domain` | PASS |
| T1482 | Domain Trust Discovery | `nltest /domain_trusts /all_trusts` | PASS |
| T1135 | Network Share Discovery | `net view \\FS01` | PASS |
| T1039 | Data from Network Shared Drive | Read benign file from `\\FS01\Finance` | PASS |

## T1057 - Process Discovery

`tasklist.exe` was executed from WS01. Sysmon Event ID 1 captured the process creation, command line, user context, and process entity identifiers. An entity-aware EQL prototype validated parent-child correlation with `cmd.exe`.
## T1069.002 - Domain Groups Discovery

WS01 queried domain groups with native `net.exe`/`net1.exe`. Telemetry showed that both binaries may appear, so the building-block detection intentionally covers both instead of requiring a fixed `net.exe -> net1.exe` relationship.

## T1482 - Domain Trust Discovery

`nltest /domain_trusts /all_trusts` was executed by `C0015\duc.user`. The behavior was captured as process-start telemetry and validated with an atomic detection rule.

## T1135 - Network Share Discovery

`net view \\FS01` successfully enumerated the `Finance` and `IT` SMB shares. This action was used as the discovery precursor for the later T1039 collection step.

## T1039 - Data from Network Shared Drive

The benign file `\\FS01\Finance\budget-q3.txt` was read from WS01. Because `type` is an internal `cmd.exe` command, an interactive shell does not necessarily create a new process for the command.

Server-side Windows Security auditing therefore provided the stronger evidence. FS01 generated Event ID 5145 with:
- user `C0015\duc.user`
- source IP `192.168.50.20`
- share `Finance`
- target `budget-q3.txt`
- successful read-related access rights

This event was ingested centrally by Elastic Agent and became the T1039 building-block signal.

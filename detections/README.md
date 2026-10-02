# Detection rule catalogue

The current suite contains **24 rules: 23 EQL rules and one KQL threshold rule**.
R14 is split into R14a/R14b; R21 is retired. **R17, R18, and R23** are high-severity
alerting rules. The other **21** are building blocks used during investigation.
This catalogue reflects the committed NDJSON metadata, not a fresh server execution check.

## Rule index

| Rule | Exported name (without C0015 prefix) | Type | Risk | Building block | Stage | Suppression grouping |
|---|---|---|---|---|---|---|
| R01 | Office Spawning a Script Host or Shell | eql | 21 | ON | S1 | — |
| R02 | Script Host Spawning Regsvr32 or Rundll32 | eql | 21 | ON | S2 | — |
| R03 | Proxy Loader Loading an Unsigned Module from a Staging Path | eql | 21 | ON | S2/S8b | — |
| R04 | Script or Proxy Writing to a Staging Path | eql | 21 | ON | S2 | — |
| R05 | Regsvr32 or Rundll32 Spawning PowerShell | eql | 21 | ON | S3/S9 | — |
| R06 | Script Host Network Egress | eql | 21 | ON | S2–S3/S9 | process.entity_id; 5m |
| R07 | Office to Mshta to Proxy Loader | eql | 21 | ON | S1–S2 | — |
| R08 | Unsigned Module Load Followed by a PowerShell Child | eql | 21 | ON | S2–S3/S8b–S9 | — |
| R09 | Proxy-Spawned PowerShell Making a Network Connection | eql | 21 | ON | S3/S9 | — |
| R10 | PowerShell Spawning Nested CMD Processes | eql | 21 | ON | S4 | host.name + process.entity_id; 5m |
| R11 | Nested CMD Launching a Discovery-Capable Tool | eql | 21 | ON | S4 | host.name + process.entity_id; 5m |
| R12 | PowerShell-Driven Discovery via Nested CMD | eql | 21 | ON | S4 | host.name + process.entity_id; 5m |
| R13 | Share Enumeration via net view or Get-SmbShare | eql | 21 | ON | S5 | process.entity_id; 5m |
| R14a | Network Logon by Non-System Account | eql | 21 | ON | S7 | host.name + winlog.event_data.TargetLogonId; 5m |
| R14b | Elevated Privileges Assigned to Non-System Account | eql | 47 | ON | S7 | host.name + winlog.event_data.SubjectLogonId; 5m |
| R15 | LSASS Access with Credential-Access Grant | eql | 47 | ON | S7b | process.entity_id; 5m |
| R16 | Admin Share Access (SMB) | eql | 21 | ON | S8a/S10 | host.name + winlog.event_data.SubjectLogonId + winlog.event_data.ShareName; 5m |
| R17 | WMI-Spawned Process Loading an Unsigned Module | eql | 73 | OFF | S8b | host.name + process.entity_id; 5m |
| R18 | Proxy-Spawned PowerShell Making an Egress Connection | eql | 73 | OFF | S3/S9 | host.name + process.entity_id; 5m |
| R19 | RDP Interactive Logon by Non-System Account | eql | 47 | ON | S12 | — |
| R20 | Portable Tool Dropped into Non-Standard Location then Executed | eql | 47 | ON | S13 | — |
| R22 | Potential Ransomware Note Creation | eql | 21 | ON | S14 | — |
| R23 | Note Spread with Same-Process Context | threshold | 73 | OFF | S14 | — |
| R24 | Transfer Tool Egress | eql | 21 | ON | S11 | — |

EQL rules run every **1 minute** with `from=now-6m`. R23 also runs every minute but
uses `from=now-10m`: at least **three distinct `file.path` values**, grouped by
`host.name` and `process.entity_id`. Suppression is configured only for rows that
list grouping keys; it must not be assumed for the whole suite.

## Behavioral scope

| Stage | Evidence and interpretation | Relevant rules |
|---|---|---|
| S1–S3 | Office → mshta → proxy loader, staged writes, unsigned module load, PowerShell child and network connection | R01–R09; R18 can also cover bootstrap egress |
| S4–S5 | Nested CMD discovery and share-enumeration command classes | R10–R13 |
| S6 | Server-side fixed-target decision in RUN-09; orchestration evidence | No dedicated endpoint rule |
| S7/S7b | Network logon, assigned privileges, and LSASS-access rights | R14a/R14b/R15; access does not prove credential extraction |
| S8a/S10 | Admin-share access checks on C$/ADMIN$; current collection uses C$ | R16; 5145 does not prove write completion or a complete file read |
| S8b | WmiPrvSE child followed by unsigned module load in the child entity | R17 |
| S9 | Proxy-spawned PowerShell followed by entity-owned egress | R18/R09; registration receipt independently supports session acceptance |
| S11a/b | Transfer-tool execution followed by network activity | R24; completed transfers require manifests and sink receipts |
| S12 | RemoteInteractive logon (4624 Type 10) | R19; session end is a separate 4634 LogonId join |
| S13 | Portable remote-access tool drop followed by execution on the same host | R20; actual query covers AnyDesk/RustDesk/TeamViewer, not ProcessHacker |
| S14 | Note creation and same-process note fan-out | R22/R23; this is impact-adjacent evidence, not proof of encryption |

R04's process predicate covers script/proxy writers. **WINWORD-originated macro
self-writes are outside R04**, although E11 can still record them.
R20 joins on host only: it does not establish that the process executed the exact
dropped binary. An analyst should cross-check path and the E11/E1 hashes when present.
The suite uses executable/command/path/filename classes; it is not wholly free of
filename predicates. Lab endpoint IPs are context, not a campaign conclusion.

## Analyst correlation guidance

These rules evaluate **raw events**. R17/R18/R23 do not consume building-block alerts
as inputs, and no full-campaign rule is implemented merely by producing BB alerts.

| Alerting rule | Supporting context for the analyst |
|---|---|
| R17 | R14a/R14b logon context, R16 handoff, earlier R12/R13 discovery |
| R18 | R05/R09 proxy ancestry, R04 staging, task execution from R10/R11 |
| R23 | R22 note paths, same process entity, impact output and recovery record |

Use [correlation architecture](../docs/correlation-architecture.md) for same-host
entity/logon keys and cross-host handoffs. E7 may be `event.category=library`;
hashes are mapped to `file.hash.sha256`. Empty entity IDs cannot establish a direct
process link. 4672 records privileged-logon context, not local-group membership.

## Import and maintenance

Import both bundles through **Elastic Security → Rules → Import rules**:

- [R01–R11 bundle](exports/c0015-rules-r01-r11.ndjson): 11 rules.
- [R12–R24 bundle](exports/c0015-rules-r12-r24.ndjson): 13 rules.

[Query sources](queries/) and the [generator](../scripts/rules/gen_rules_ndjson.ps1)
are version controlled. IDs are derived from rule names: re-importing an unchanged
name is stable, while a rename requires migration of the old rule. Offline component
tests do not validate EQL execution; live execution and matches belong to run evidence.

## Replay coverage and volume

See [RUN-09](../reports/reference-run-20261002-09.md) for the latest evidence and
[RUN-07](../reports/reference-run-20261002-07.md) for the tuning reference. R19 has
positive evidence in 06–09. RUN-05 also contains T10 logons, but R19 coverage began
after its window. R22/R23/R24 were added before RUN-07; do not retroactively require
them in 05/06.

Distinguish stored alert documents, `kibana.alert.suppression.docs_count`, and unique
entities/sequences. A polling entity can create many connections, and overlapping
look-back windows can revisit events. Historical document counts are not counts of
independent incidents or a measured false-positive rate.

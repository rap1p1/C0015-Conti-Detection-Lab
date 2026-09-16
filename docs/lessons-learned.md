# Lessons Learned

## Telemetry is not the same as behavior visibility

A command can execute successfully without producing a new Process Create event. For example, `type` is a built-in command handled by an already-running `cmd.exe`. Sysmon Event ID 1 therefore cannot be expected to reveal every interactive shell command.

The defensive question should be "can the behavior be observed?" rather than "can the exact command string be observed?" In the T1039 case, FS01 Event ID 5145 provided stronger evidence of actual remote file access.

## Server-side logs can be stronger than client-side intent

Client telemetry can show a command attempting to access a resource. Server-side auditing can confirm that access was actually granted and identify the user, source IP, share, target file, and requested access rights.

## Process identity matters

Numeric PIDs can be reused. Entity-aware EQL using `process.entity_id` and `process.parent.entity_id` produced stronger parent-child correlation than PID-only logic.

## Time constraints are real detection logic

An EQL sequence can fail even when parent-child identity is correct if the first event is older than `maxspan`. Long-lived interactive shells demonstrated why temporal assumptions must be tested instead of increased only to force a match.

## Legitimate tools require behavioral context

`cmd.exe`, `net.exe`, `net1.exe`, `nltest.exe`, and `tasklist.exe` are legitimate Windows utilities. Process-name-only detections are noisy and weak. Command line, user, host role, temporal clustering, and follow-on behavior provide the needed context.

## Building blocks should optimize recall, correlation should optimize confidence

The account/group building block intentionally covers both `net.exe` and `net1.exe` and multiple account/group discovery subcommands. This creates some duplicate or benign signals, but the correlation layer uses distinct behavior families to prevent raw alert count from becoming confidence.

## Collection filtering and detection tuning are different

A Sysmon exclusion removes telemetry before it reaches the SIEM. A detection exception or correlation condition keeps the event available for hunting and investigation while reducing alerts. Source-side exclusions should therefore remain narrow.

## Cross-host detection requires data from both sides

WS01 discovery telemetry alone did not prove that a file on FS01 was read. Installing Elastic Agent on FS01 and enabling Detailed File Share auditing converted a local Event Viewer artifact into centralized evidence usable by Elastic Security.

## Troubleshoot the telemetry path before reinstalling agents

Several apparent Elastic problems were actually routing, VMware NAT, Tailscale, CA-trust, or local daemon-state problems. The reliable troubleshooting order is endpoint -> route/gateway -> overlay -> Fleet/Elasticsearch -> agent -> integration.

## Detection engineering is iterative

The project repeatedly used the same cycle: observe raw telemetry, inspect ECS mappings, write a prototype, test edge cases, analyze false positives, tune, and only then promote logic into a rule. The final correlation is stronger because the atomic experiments were preserved rather than skipped.

## Licensing can influence detection design

Native alert suppression was unavailable under the current Elastic license. The correlation therefore uses a sliding look-back window plus a freshness condition on the newest contributing signal to reduce repeated correlation alerts without hiding the underlying atomic data.

## Portfolio evidence should be curated

Atomic-rule screenshots and intermediate experiments are useful repository evidence, but the report should emphasize a small number of high-value screenshots: architecture, representative raw telemetry, cross-host evidence, and the final analyst-facing correlation alert.

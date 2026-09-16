# Lessons Learned

## Telemetry is not the same as visibility everywhere

A local event can exist without being visible in the SIEM. FS01 initially generated Event ID 5145 locally, but the event did not become centrally searchable until Elastic Agent was installed and enrolled on FS01.

## Sysmon does not record every command typed into a shell

Sysmon Event ID 1 records process creation. Interactive `cmd.exe` built-ins such as `type`, `dir`, and `cd` may execute inside an existing shell without creating a new process.

Detection should focus on the observable security-relevant behavior, not assume every typed command becomes process telemetry.

## Server-side evidence can be stronger than client command-line evidence

For T1039, FS01 Event ID 5145 directly proved that `duc.user` from WS01 accessed `budget-q3.txt` over SMB. That evidence was stronger than trying to infer the read from an interactive command shell.

## `net.exe` and `net1.exe` should not be modeled as a fixed chain

Both binaries appeared in this lab. A production-oriented building block should cover both instead of requiring a universal `net.exe -> net1.exe` relationship.
## Building blocks should optimize for recall

Low-confidence atomic rules can be broader and noisier than final analyst-facing rules. Precision is recovered at the correlation layer by requiring multiple distinct behavior families and shared context.

## Count distinct behaviors, not raw alert volume

A single action may create multiple events or alerts. The final correlation uses distinct rule/behavior families so duplicate `net.exe`/`net1.exe` and SMB records do not inflate confidence.

## Cross-host detections need careful grouping

Discovery occurred on WS01 while the SMB collection event was recorded on FS01. Grouping only by `host.name` would split the same attack story. User and network context are required to bridge the hosts.

## Detection licensing affects engineering choices

Native alert suppression was unavailable under the current license. A freshness condition on the latest contributing signal was used with a sliding look-back window to reduce duplicate correlation alerts.

## Tune collection narrowly

Broad source-side exclusions remove evidence permanently. When possible, retain useful telemetry and reduce noise in detection logic, exceptions, aggregation, or correlation instead.

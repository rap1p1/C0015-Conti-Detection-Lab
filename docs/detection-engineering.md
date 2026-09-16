# Detection Engineering

## Design goal

The lab separates low-confidence atomic analytics from analyst-facing correlation. Atomic rules favor recall inside a bounded behavior family; the final rule combines multiple distinct signals to increase confidence and reduce noise.

## Atomic building blocks

| Rule | ATT&CK | Severity | Risk |
|---|---|---:|---:|
| Windows Process Discovery via Tasklist | T1057 | Low | 15 |
| Domain Groups Discovery via Net | T1069.002 | Low | 20 |
| Domain Trust Discovery via NLTest | T1482 | Low | 20 |
| Network Share Discovery via Net View | T1135 | Low | 20 |
| Remote SMB File Read from Network Share | T1039 | Low | 25 |

Atomic rules have no notification actions. Their purpose is to create reusable signals for correlation and investigation.

## T1057 - Process Discovery

```kql
event.type : "start"
and process.name : "tasklist.exe"
```

This signal is intentionally broad because `tasklist.exe` is common administrative activity and is not treated as malicious by itself.

## T1069.002 - Account/Group Discovery

```kql
event.type : "start"
and process.name : ("net.exe" or "net1.exe")
and (
  process.command_line : *group*
  or process.command_line : *user*
  or process.command_line : *localgroup*
)
```

The rule covers both `net.exe` and `net1.exe`. The lab observed `cmd.exe -> net.exe -> net1.exe`, but that implementation detail is not required by the analytic. The building block is intentionally broader than only `Domain Admins` so correlation can provide precision later.

## T1482 - Domain Trust Discovery

```kql
event.type : "start"
and process.name : "nltest.exe"
and (
  process.command_line : *domain_trusts*
  or process.command_line : *all_trusts*
  or process.command_line : *trusted_domains*
)
```

## T1135 - Network Share Discovery

```kql
event.type : "start"
and process.name : ("net.exe" or "net1.exe")
and process.command_line : *view*
```

## T1039 - Network Share File Access

```kql
event.code : "5145"
and event.outcome : "success"
and event.type : "access"
and file.name : *
and source.ip : *
```

The T1039 rule uses FS01 server-side auditing. This is stronger evidence of actual remote file access than a client-side shell command alone.

## Duplicate handling

One action can produce multiple atomic alerts. The lab observed duplicate `net.exe`/`net1.exe` signals and multiple 5145 events for a single SMB read. The correlation therefore counts distinct behavior families rather than raw alert count.

This preserves recall at the atomic layer while preventing duplicate events from artificially increasing correlation confidence.

## Detection #1 - Cross-host correlation

**Rule:** `Suspicious Discovery and Network Share Collection Chain`
**Severity:** Medium
**Risk score:** 60

The ES|QL rule reads Elastic Security alerts from the five atomic rules, maps each rule to a behavior family, and aggregates by `user.name`.

Required conditions:
- at least four distinct behavior families;
- at least one network-share collection signal;
- activity across at least two hosts;
- at least one source IP in contributing alerts;
- the newest contributing signal must be recent enough for the active correlation window.

ATT&CK mapping:
- T1057 Process Discovery
- T1069.002 Domain Groups
- T1482 Domain Trust Discovery
- T1135 Network Share Discovery
- T1039 Data from Network Shared Drive

The current production-like schedule is intended to run every five minutes with a fifteen-minute look-back. During validation, intervals were temporarily reduced to one minute.

## Noise controls and validation

Atomic alerts are expected to be noisy enough to preserve useful recall. The final rule reduces noise through aggregation, required collection activity, multi-host context, a bounded look-back window, and a freshness condition on the latest contributing signal.

Native alert suppression was not available under the current license, so duplicate correlation alerts are controlled at the query and schedule layer instead.

Final validation produced one Medium alert after replaying the full chain. The final alert is the primary report evidence; atomic alerts are retained as supporting repository evidence.

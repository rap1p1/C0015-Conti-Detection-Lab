# Investigation

## Detection #1 case study

The first analyst-facing detection correlates Windows discovery on WS01 with subsequent SMB file access on FS01.

### Observed chain

```text
C0015\duc.user on WS01
  -> tasklist.exe
  -> net.exe / net1.exe account-group discovery
  -> nltest.exe domain-trust discovery
  -> net view \\FS01
  -> SMB access to \\FS01\Finance\budget-q3.txt
```

The discovery activity is observed primarily through Sysmon Process Create telemetry on WS01. The collection step is confirmed independently on FS01 with Windows Security Event ID 5145.

## Server-side evidence

The relevant 5145 event contained:
- account: `C0015\duc.user`
- source address: `192.168.50.20`
- share: `\\*\Finance`
- target: `budget-q3.txt`
- local path: `C:\Shares\Finance\budget-q3.txt`
- successful read-related access rights

## Correlation result

The final ES|QL correlation produced one Medium-severity alert with risk score 60 after the five atomic behavior families fired in the same short investigation window.

The correlation grouped by `user.name`, required collection activity, required multiple hosts, and used distinct behavior families to avoid double-counting duplicate atomic alerts.

## Analyst interpretation

No single atomic signal proves malicious activity. `tasklist`, `net`, `nltest`, and SMB file access are legitimate administrative behaviors. Confidence increases because the same identity performs several discovery behaviors and then accesses a remote share within a short period.

The expected analyst workflow is:
1. validate the user and source workstation;
2. inspect the discovery sequence and parent processes;
3. pivot to FS01 5145 events;
4. confirm the remote target and accessed files;
5. review whether the access was expected for the identity;
6. search for follow-on lateral movement, staging, exfiltration, or persistence.

## Current limitation

The correlation proves same-user, multi-host activity and presence of a source IP, but it does not yet mathematically join the FS01 `source.ip` back to the exact WS01 host identity. This is a future enrichment/correlation improvement.

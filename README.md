# C0015 Conti Detection Lab

A safe adversary-emulation and detection-engineering lab based on MITRE ATT&CK campaign C0015. The project focuses on how Windows and Active Directory behaviors become telemetry, ECS-normalized events, atomic detections, cross-host correlations, and analyst-facing alerts in Elastic Security.

## Current milestone

Detection #1 is complete end to end: multiple Windows discovery behaviors on WS01 are correlated with SMB file access on FS01 into a single Medium-severity Elastic Security alert.

**Detection:** `Suspicious Discovery and Network Share Collection Chain`
**Severity:** Medium
**Risk score:** 60
**Status:** PASS

## Lab architecture

| Host | Role | Address |
|---|---|---|
| DC01 | AD DS + DNS | 192.168.50.10 |
| WS01 | Initial victim workstation | 192.168.50.20 |
| FS01 | SMB file server | 192.168.50.30 |
| Kali | Isolated-lab gateway / Tailscale router | 192.168.50.100 |
| ELASTIC01 | Elasticsearch, Kibana, Fleet Server | Tailscale 100.77.46.126 |

Domain: `c0015.lab`
NetBIOS: `C0015`

## Detection #1 coverage

| ATT&CK | Behavior | Atomic analytic |
|---|---|---|
| T1057 | Process Discovery | `tasklist.exe` |
| T1069.002 | Domain Groups Discovery | `net.exe` / `net1.exe` account-group discovery |
| T1482 | Domain Trust Discovery | `nltest.exe` trust discovery |
| T1135 | Network Share Discovery | `net view` |
| T1039 | Data from Network Shared Drive | Windows Security 5145 remote file access |

The correlation deliberately counts distinct behavior families rather than raw alert volume, preventing duplicate `net.exe`/`net1.exe` and repeated 5145 events from inflating the chain.

## Detection pipeline

```text
ATT&CK behavior
  -> Windows / Sysmon / Security telemetry
  -> Elastic Agent + Windows integration
  -> ECS-normalized events
  -> low-confidence atomic detections
  -> ES|QL cross-host correlation
  -> analyst-facing Elastic Security alert
```

The final rule requires multiple distinct discovery behaviors, at least one network-share collection signal, activity spanning multiple hosts, and a recent contributing signal within the correlation window.

## Repository layout

```text
configs/      Elastic, Fleet, and Sysmon configuration
 detections/   Atomic and correlation queries
 diagrams/     Architecture diagrams
 docs/         Architecture, emulation, detection, investigation, journal, experiments
 evidence/     Sanitized screenshots and supporting artifacts
 scripts/      Safe lab automation and helper scripts
```

## Documentation

- [Architecture](docs/architecture.md)
- [Attack emulation](docs/attack-emulation.md)
- [Detection engineering](docs/detection-engineering.md)
- [Investigation](docs/investigation.md)
- [Experiments](docs/experiments.md)
- [Lab journal](docs/lab-journal.md)
- [Lessons learned](docs/lessons-learned.md)

## Safety boundary

This repository uses only owned virtual machines, benign commands, dummy files, and safe substitutes. Real Conti/Bazar malware, destructive encryption, credential theft, and uncontrolled targeting are out of scope. Secrets, enrollment tokens, certificate private keys, and SSH private keys are excluded from version control.

## Project status

The lab is in active development. Detection #1 is complete; additional C0015 techniques will be emulated and analyzed in later milestones.

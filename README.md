# C0015 Conti Detection Lab

A defensive security lab that safely emulates selected behaviors from MITRE ATT&CK campaign C0015 and studies how those behaviors become telemetry, detections, alerts, and investigations in Elastic Security.

The project is intentionally malware-free. It reproduces observable behaviors with native Windows tooling and benign test data instead of executing Conti, Bazar, or other real malware.

## Current milestone

Detection #1 is complete end-to-end:

**Suspicious Discovery and Network Share Collection Chain**

The correlation combines five low-confidence atomic detections into one analyst-facing alert:

- T1057 - Process Discovery
- T1069.002 - Permission Groups Discovery: Domain Groups
- T1482 - Domain Trust Discovery
- T1135 - Network Share Discovery
- T1039 - Data from Network Shared Drive

Final correlation severity: **Medium**  
Risk score: **60**  
Validation result: **PASS**
## Lab architecture

- **DC01** - Active Directory Domain Services + DNS, `192.168.50.10`
- **WS01** - Windows 10 victim workstation, `192.168.50.20`
- **FS01** - Windows file server, `192.168.50.30`
- **Kali** - isolated-lab gateway and Tailscale router, `192.168.50.100`
- **ELASTIC01** - Elasticsearch, Kibana and Fleet Server on Ubuntu in Azure

Active Directory domain: `c0015.lab`  
NetBIOS domain: `C0015`

Windows endpoints intentionally have no general Internet default gateway. Telemetry is routed through Kali and Tailscale to ELASTIC01.

## Detection pipeline

```text
Windows activity
  -> Sysmon / Windows Security auditing
  -> Elastic Agent
  -> Fleet / Integrations
  -> ECS normalization
  -> Elasticsearch
  -> Atomic detection rules
  -> ES|QL correlation
  -> Elastic Security alert
```
## Repository structure

```text
configs/                  Elastic, Fleet and Sysmon configuration
 detections/
   atomic/                Low-confidence building-block queries
   correlations/          Higher-confidence multi-event correlations
   eql/                   EQL prototypes and experiments
 docs/
   architecture.md
   attack-emulation.md
   detection-engineering.md
   experiments.md
   investigation.md
   lab-journal.md
   lessons-learned.md
 evidence/sanitized-screenshots/
 scripts/
```

## Design principles

- ATT&CK is used as a behavior catalogue, not as a checklist of alerts.
- Atomic detections favor recall and are treated as building blocks.
- Analyst-facing alerts are created from higher-confidence correlations.
- Raw telemetry is retained whenever practical; noise is tuned narrowly.
- Cross-host evidence is preferred when the server can prove the action more reliably than the client process log.
- No real malware, destructive ransomware, credential theft, or unsafe payloads are executed.
## Documentation

- [Architecture](docs/architecture.md)
- [Attack emulation](docs/attack-emulation.md)
- [Detection engineering](docs/detection-engineering.md)
- [Investigation](docs/investigation.md)
- [Experiments](docs/experiments.md)
- [Lab journal](docs/lab-journal.md)
- [Lessons learned](docs/lessons-learned.md)

## Security notes

Secrets, enrollment tokens, private keys, certificate private material, and environment files must never be committed. The repository `.gitignore` explicitly excludes common sensitive artifacts.

The project is a defensive learning environment. All ATT&CK behaviors are emulated against systems and data owned by the lab operator.

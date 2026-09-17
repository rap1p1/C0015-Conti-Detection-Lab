# C0015 Conti Detection Lab

An evidence-driven reconstruction of [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/) for detection engineering and incident-response training. The project rebuilds the documented intrusion chain — Bazar → Cobalt Strike → Conti — using controlled lab-safe surrogates while preserving the original campaign evidence as historical ground truth.

## What Was C0015?

C0015 was a multi-stage intrusion documented by MITRE ATT&CK and The DFIR Report in which operators used **Bazar** for initial access and persistence, transitioned to **Cobalt Strike** for command-and-control and lateral movement, and deployed **Conti** ransomware for final impact. The campaign followed a structured lifecycle:

```text
Bazar bootstrap and callback
  → Cobalt Strike tasking and discovery
  → WMI lateral movement to a file server
  → data collection and exfiltration via Rclone
  → RDP / secondary remote access
  → Conti ransomware deployment
```

## What This Lab Reconstructs

The lab reproduces the C0015 intrusion lifecycle on owned virtual machines using safe equivalents. Each campaign stage is mapped to its historical role, and the corresponding Windows, Active Directory, network, and file-system mechanisms are executed live to generate real telemetry.

| Campaign Stage | Historical Software | Lab Surrogate | Fidelity |
|---|---|---|---|
| Initial execution / bootstrap | Bazar loader chain | Controlled document → script → DLL bootstrap | Role preserved; original malware not executed |
| C2 tasking and discovery | Cobalt Strike Beacon | Apache CALDERA agent / controlled tasking surrogate | Role preserved; actual Cobalt Strike not used |
| Lateral movement | WMI + rundll32 | Native WMI execution with benign DLL | Mechanism reproduced |
| Collection / exfiltration | Rclone to cloud storage | Rclone or equivalent to internal destination | Partial — cloud destination not used |
| Remote access | RDP / AnyDesk | Native RDP between lab hosts | RDP reproduced; AnyDesk documented only |
| Impact | Conti ransomware | Bounded impact simulator on disposable corpus | Behavioral invariants preserved; no real encryption |

## Lab Architecture

```text
VMnet2 — 192.168.50.0/24 (host-only, no DHCP)
```

| Host | Role | Address |
|---|---|---|
| DC01 | Active Directory, DNS | 192.168.50.10 |
| WS01 | Initial victim workstation | 192.168.50.20 |
| FS01 | File server / lateral-movement target | 192.168.50.30 |
| Kali | Operator host / Tailscale router | 192.168.50.100 |
| ELASTIC01 | Elasticsearch, Kibana, Fleet Server | Tailscale network |

Domain: `c0015.lab` / NetBIOS: `C0015`

Telemetry flows from Windows endpoints through Elastic Agent → Kali (Tailscale router) → ELASTIC01 → Elastic Security.

## Detection Engineering Methodology

The project evaluates detections through controls, variations, correlations, containment, and recovery.

```text
C0015 forensic evidence
  → behavioral specification
  → safe live reconstruction
  → raw telemetry collection
  → baseline detection
  → controlled variation
  → detection miss / sensor gap analysis
  → improved analytic
  → containment and recovery validation
```

Detection layers:

```text
Atomic analytics (low-confidence building blocks)
  → behavioral correlations (cross-host, multi-signal)
  → campaign-level investigation (full chain reconstruction)
```

## Planned Phases

| Phase | Description | Status |
|---|---|---|
| 0 | Ground truth and sensor readiness | Partial |
| 1 | Initial access / bootstrap reconstruction | Planned |
| 2 | Bazar Stage Reconstruction | Planned |
| 3 | Cobalt Strike Stage Reconstruction | Planned |
| 4 | Discovery and target selection | Partial (atomics complete) |
| 5 | Privileged-access lab prerequisite | Planned |
| 6 | WMI lateral movement | Planned |
| 7 | Controlled DLL injection reconstruction | Planned |
| 8 | Collection and transfer | Planned |
| 9 | RDP / secondary remote access | Planned |
| 10 | Conti Impact Reconstruction | Planned |
| 11 | Prevention, containment, and recovery | Planned |

## Project Structure

```text
C0015-Conti-Detection-Lab/
├── README.md                  Project landing page
├── docs/
│   ├── plan.md                Primary build plan and source of truth
│   ├── architecture.md        Infrastructure and telemetry documentation
│   ├── attack-emulation.md    C0015 lifecycle reconstruction stages
│   ├── detection-engineering.md  Detection architecture and analytics
│   ├── investigation.md       Investigation methodology
│   ├── experiments.md         Structured experiment ledger
│   └── lab-journal.md         Major milestones
├── detections/
│   ├── atomic/                KQL building-block detections
│   ├── correlations/          ES|QL cross-host correlations
│   └── eql/                   EQL parent-child validation queries
├── configs/
│   ├── elastic/
│   ├── fleet/
│   └── sysmon/                Sysmon configuration
├── diagrams/
├── evidence/
│   └── sanitized-screenshots/
└── scripts/
```

## Evidence and Fidelity Philosophy

Every campaign claim is classified as:

| Classification | Meaning |
|---|---|
| **OBSERVED** | Directly supported by campaign sources |
| **INFERRED** | Reasoned from evidence with documented uncertainty |
| **UNKNOWN** | Insufficient evidence; gap remains unresolved |
| **LAB ASSUMPTION** | Prerequisite introduced to make the lab executable |
| **SUPPLEMENTAL** | Useful experiment not counted as core C0015 coverage |

## Documentation

- [Build Plan](docs/plan.md) — primary project source of truth
- [Architecture](docs/architecture.md)
- [Attack Emulation](docs/attack-emulation.md)
- [Detection Engineering](docs/detection-engineering.md)
- [Investigation](docs/investigation.md)
- [Experiments](docs/experiments.md)
- [Lab Journal](docs/lab-journal.md)

## Current Status

The lab is in active development. The discovery-to-collection detection milestone is complete. The project is preparing for bootstrap reconstruction, CALDERA integration, and the remaining C0015 lifecycle phases.

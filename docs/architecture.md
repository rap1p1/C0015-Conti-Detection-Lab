# Architecture — C0015 Conti Detection Lab

## Overview

This document defines the authoritative infrastructure and telemetry architecture for the C0015 Conti Detection Lab. The lab reconstructs the C0015 intrusion lifecycle on isolated virtual machines, generating real Windows, Active Directory, and network telemetry for analysis in Elastic Security.

Statuses in this document reflect the verified handoff of 2026-09-26. Nothing on the virtual machines was re-verified in the session that produced this revision; anything marked unknown or pending remains so and must not be treated as confirmed.

## Network Topology

The lab uses a single flat host-only segment:

```text
VMnet2 — 192.168.50.0/24
  Type:   Host-only
  DHCP:   Disabled
  Domain default gateway: None
```

Windows endpoints carry two adapters:

| Adapter | Network | Purpose | Observed values |
|---|---|---|---|
| Ethernet0 | VMware NAT (Internet) | Fetch installers and updates | WS01 observed at 192.168.106.136, gateway 192.168.106.2 |
| Ethernet1 | VMnet2 (192.168.50.0/24) | Domain traffic | WS01 192.168.50.20, FS01 192.168.50.30, DNS 192.168.50.10, no gateway |

Ethernet1 carries the lower route metric so domain traffic prefers the lab NIC; outbound access (downloads, updates) goes through Ethernet0 and the NAT gateway.

Because all lab systems share one flat subnet, traffic between endpoints does not traverse a router or firewall. Network-level visibility is therefore limited to host-based capture (for example Sysmon Event ID 3) or packet captures defined per experiment; there is no inline network security device available for blocking tests.

## Hosts

| Host | Address | Role |
|---|---|---|
| DC01 | 192.168.50.10 | Domain controller: Active Directory Domain Services, DNS, LDAP, Kerberos |
| WS01 | 192.168.50.20 | Initial victim workstation, primary emulation origin |
| FS01 | 192.168.50.30 | File server and lateral-movement target |
| Kali | 192.168.50.100 | Operator host (planned), Tailscale subnet router |
| ELASTIC01 | Tailscale network | Elasticsearch, Kibana, Fleet Server |

### DC01

Active Directory Domain Services, DNS, LDAP, and Kerberos for the `c0015.lab` domain, verified (an `nltest /dsgetdc:c0015.lab` check returns PASS from WS01 and FS01). The operating system edition is unknown. The campaign never interacts with DC01; its role is telemetry only.

### WS01

Windows 10, joined to `c0015.lab`, and the first victim. Adapter layout: Ethernet0 on VMware NAT (observed 192.168.106.136, gateway 192.168.106.2, used to fetch installers and updates) and Ethernet1 on VMnet2 (DNS 192.168.50.10, no gateway, lower metric for domain traffic). Microsoft Word installation is pending verification (Office Deployment Tool, Word-only configuration).

### FS01

Windows 10 Pro (build 19045), joined to `c0015.lab`. Hosts the SMB shares Finance and IT (see Shares below). `duc.user` is a member of the Finance group; `it.admin` is a member of IT-Admins and is not a domain administrator. Whether `it.admin` has local administrator rights on FS01 is unknown; this is an M-1 gate for the WMI phase.

### Kali

Planned operator host at 192.168.50.100. Kali is expected to act as the lab-facing gateway and Tailscale subnet router, with a NAT interface for outbound connectivity. It is part of the telemetry path to ELASTIC01 (see Telemetry Path).

### ELASTIC01

Runs Elasticsearch 9.5.3, Kibana, and Fleet Server (https://100.77.46.126:8220) on the Tailscale network. The agent policy is `C0015-Windows-Endpoints` in namespace `c0015`; the WS01 and FS01 agents report Healthy. Enrollment uses the dedicated lab CA certificate (`fleet-ca.crt`), delivered out of band.

## Active Directory and Identity

Domain: `c0015.lab` (NetBIOS `C0015`).

| Account | Group | Role |
|---|---|---|
| `C0015\duc.user` | Finance | Standard user, initial victim context |
| `C0015\it.admin` | IT-Admins | Administrative account for controlled experiments (not a domain administrator) |

## SMB Shares (FS01)

| Share | Local path | Permission | Contents |
|---|---|---|---|
| `\\FS01\Finance` | `C:\Shares\Finance` | Change for the Finance group | `budget-q3.txt`, `payroll-notes.txt` |
| `\\FS01\IT` | `C:\Shares\IT` | Change for IT-Admins | `server-inventory.txt` |

The Finance share holds benign dummy files used for safe collection and impact experiments.

## Sysmon Telemetry Configuration

This section is critical: it records exactly what is deployed, what is committed, and what must be reconciled. It is the working reference for Sysmon coverage on WS01 and FS01; the operational application, backup, and verification instructions are deliverables of the Sysmon telemetry guide, provided outside this repository.

### Installed baseline and configuration hash mismatch

WS01 and FS01 run Sysmon 15.21 (schema 4.91), installed at `C:\Tools\sysmon64.exe` with the active configuration at `C:\Tools\sysmon-c0015.xml`. The live baseline enables Event IDs 1, 3, 11-14, and 17-22 and keeps Event IDs 7 (ImageLoad) and 10 (ProcessAccess) disabled, with exclusions: Event ID 3 for DNS to DC01:53, Event ID 11 for Elastic/Edge/diagnostic paths, a Registry include for Run/RunOnce/Services/Classes/Environment, and a Registry exclude for VMware Tcpip.

The configuration hashes do not line up:

- Live configuration on the VMs: `D30CD93C...`
- Previously uncommitted working-tree variant: `42BC6998...`

The live deployment is therefore a third variant (baseline plus exclusions, Event IDs 7 and 10 disabled) that matches neither the committed profiles nor the earlier uncommitted variant. This must be reconciled in M-1 before S2 and S9, which require scoped Event ID 7 coverage, and before the S13b study, which relies on Event ID 10.

### Committed Sysmon profiles

Two complete, mutually exclusive profiles live under `configs/sysmon/`; never load both at once.

- `sysmon-c0015-balanced.xml` — **BALANCED** (routine): Event IDs 1, 3, 11-14, 17-22 broad with the lab
  exclusions; Event ID 7 (ImageLoad) scoped to lab staging/tooling paths; Event ID 10 (ProcessAccess)
  scoped to the detection-study targets (`lab-target.exe`, `lsass.exe` — telemetry only, no interaction);
  Registry scoped to Run/RunOnce/Services/Classes/Environment; Event IDs 23/24/27/28 disabled (archive /
  clipboard / blocking features); E26 deletion logging on without archive.
- `sysmon-c0015-capture.xml` — **CAPTURE** (bounded observation): all event types broad; Event IDs 7, 10
  and 12-14 deliberately unfiltered; Event IDs 23/24/27/28 disabled as above; `DnsLookup=false`; hashes
  SHA256+IMPHASH. Use only for short first-pass coverage checks, measure load, then switch back to BALANCED.
- `DnsLookup` is false (reverse lookups disabled; Event ID 22 DNS queries remain enabled).
- Hash algorithms: SHA256 and IMPHASH. Schema 4.91.
- No IP, DLL-name, pipe-name, filename, or Microsoft-signature filtering.

The CAPTURE profile is intended for bounded evidence-collection sessions: it supports Event ID 7 hash evidence for S2 and S9 and Event ID 10 evidence for the S13b study. Because Event IDs 7, 10, and 12-14 are unfiltered, it can produce substantial CPU, disk, and ingestion load; measure it first.

### BALANCED profile

The Sysmon telemetry guide also defines a BALANCED profile that scopes Event IDs 7, 10, and 12-14 (by process, module path, signature, registry area, and write source) for routine collection. The BALANCED profile is provided outside this repository (planned); it is not yet a committed file.

### Deployment flow

The two profiles are alternative, complete configurations; never load both at once. The recommended flow is: deploy the CAPTURE profile for observation sessions, measure the resulting load, then switch to the BALANCED profile for routine collection.

Apply a profile with `sysmon64.exe -c <file>`, always backing up the currently active configuration first. The backup, application, post-load verification, and rollback instructions are deliverables described in the Sysmon telemetry guide.

### Observability status model

A configuration only defines what Sysmon is able to observe; it does not guarantee that every event reaches Elastic. Track three distinct states separately:

- CONFIGURED — the event type is enabled in the applied configuration.
- LOCAL OBSERVED — the event is present in the local Windows event log.
- INGEST VERIFIED — the event was located in Elastic (Discover).

An agent reporting Healthy proves only that the agent runs; it does not prove that each log source is ingested.

## Additional Audit and Log Requirements

These requirements come from the Sysmon telemetry guide and apply in addition to the Sysmon XML. Select Advanced Audit Policy in Group Policy and verify the effective policy on each machine; checking the GPO name alone is not sufficient.

| Host | Source / event | Collection condition |
|---|---|---|
| WS01, FS01 | Security 4624/4625/4648/4672/4634/4647 | Audit Logon, Logoff, Special Logon; success/failure per subcategory |
| WS01, FS01 | Security 4688 | Audit Process Creation, with command line in process creation events for correlation |
| FS01 | Security 5140/5145 | Audit File Share and Detailed File Share; success/failure |
| FS01 | Security 4663 (4656/4660 supplemental) | Audit File System with a SACL on Finance, IT, and relevant corpus/staging folders; select ReadData/WriteData/Delete per objective |
| DC01 | Security 4768/4769/4771, 4776 | Kerberos Authentication Service, Service Ticket Operations, Credential Validation |
| RDP target | Security 4624 (Type 10), 4778/4779 | Logon and Other Logon/Logoff Events; also TerminalServices LocalSessionManager and RemoteConnectionManager operational channels |
| WS01, FS01 | PowerShell Operational 4104, 4103 | Script Block Logging and Module Logging; PowerShellCore/Operational if pwsh is present |
| WS01, FS01 | WMI-Activity/Operational | Enable the channel and ingest; record completeness depends on operation and build |
| WS01, FS01 | System 7045/7036; Security 4697 when configured | Service install/change events; 4697 requires Audit Security System Extension |
| WS01, FS01 | Defender/Operational and application logs | Identify blocked activity or interrupted observation |

SACLs must be placed on the relevant data folders only; do not enable auditing for every file on C: merely to satisfy this table.

## Elastic Ingest Verification

In the `C0015-Windows-Endpoints` policy, confirm that the Windows integration ingests `Microsoft-Windows-Sysmon/Operational` with no legacy Event ID allowlist and no processor drops that would lose Event IDs 7, 10, or 29. Ingest Security and System through the appropriate integrations and add dedicated channels only where no input exists. Do not create two inputs for the same channel without checking for duplicates.

Field preservation requirements (when supported by the integration and present in the event): raw XML / `event.original`; `host.id` / `host.name`; `provider` / `channel`; `event.code`; RecordID; `UtcTime`; `ProcessGuid` / `ParentProcessGuid`; `SourceProcessGUID` / `TargetProcessGUID`; `Image` / `ImageLoaded`; hashes and signatures; `SourceIp` / `DestinationIp` and ports; `TargetFilename` / `TargetObject`; `LogonId` / `LogonGuid`. Do not assume the same ECS fields exist identically across every dataset.

## Telemetry Path

```text
WS01 / FS01 (Elastic Agent)
  -> Kali (Tailscale subnet router / NAT outbound)
  -> Fleet Server on ELASTIC01
  -> Elasticsearch
  -> Kibana / Elastic Security
```

Endpoint Elastic Agents on WS01 and FS01 ship under the `C0015-Windows-Endpoints` policy (namespace `c0015`) to Fleet Server on ELASTIC01, reached through Kali acting as the Tailscale subnet router (with a NAT interface for outbound connectivity), and are analyzed in Kibana / Elastic Security.

## Repository Components

| Component | Location | Status |
|---|---|---|
| C2 communication simulator (foothold beacon channel) | `scripts/c2sim_v2.py` | Tested |
| Artifact, hash, manifest, receipt, and scorecard tooling | `scripts/lab_tools.py` | In repository |
| Synthetic telemetry replay fixtures (replay-only) | `scripts/fixtures/` | 12 fixtures and checker |
| Run ledger schema and templates | `evidence/run-ledger/` | Schema forbids secrets |
| Benign, config-driven payloads: macro, HTA, DLL, beacon, bounded impact | `payloads/` | Offline-validated |
| Detection content: atomic KQL, correlation ES|QL, EQL prototypes | `detections/` | In repository |
| Sysmon configuration: committed baseline and CAPTURE profile | `configs/sysmon/` | Committed |

Detailed blueprints and runbooks are documented in `docs/attack-chain-plan.md`; the attack chain and stage definitions (S2, S9, S13b) in `docs/attack-chain-plan.md`; correlation design in `docs/correlation-architecture.md`.

## Operator C2

The operator command-and-control decision is: Apache CALDERA as the primary operator C2, Sliver as an optional alternative, and Havoc excluded. CALDERA is the controlled tasking and orchestration surrogate that reproduces the command-and-control workflow of the reconstructed campaign with observable, bounded operations; it is not Cobalt Strike. The decision and payload details are documented in `docs/payloads-and-c2.md`. Operator C2 is not yet deployed.

## Trust and Certificate Model

Fleet Server and Elasticsearch are reached over TLS. Windows agents trust the lab CA that signed the Fleet Server certificate; enrollment uses the dedicated lab CA certificate (`fleet-ca.crt`), delivered out of band. Private keys, enrollment tokens, and certificate materials are excluded from version control and from this repository.

## Operational Boundary

The lab executes controlled behaviors only on owned virtual machines, using benign commands, dummy data, and safe substitutes. Out of scope are: the original Bazar/Conti malware, cracked Cobalt Strike, destructive encryption, credential theft from system processes, and uncontrolled external targeting.

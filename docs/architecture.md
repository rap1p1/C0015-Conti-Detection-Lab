# Architecture

## Overview

This document defines the authoritative infrastructure for the C0015 Conti Detection Lab. The lab reconstructs the C0015 intrusion lifecycle on isolated virtual machines, generating real Windows, Active Directory, and network telemetry for analysis in Elastic Security.

## Network

```text
VMnet2 — 192.168.50.0/24
  Type: Host-only
  DHCP: Disabled
  Gateway: None (Windows endpoints have no default Internet route)
```

All lab systems share a single flat subnet. This is a known limitation: same-subnet traffic between endpoints does not traverse a routing device, which limits network-level visibility to host-based packet capture or span configurations.

## Systems

| Host | Address | Role |
|---|---|---|
| DC01 | 192.168.50.10 | Active Directory Domain Services, DNS, authentication telemetry |
| WS01 | 192.168.50.20 | Initial victim workstation — primary emulation origin |
| FS01 | 192.168.50.30 | File server, lateral-movement target, backup-role surrogate |
| Kali | 192.168.50.100 | Operator host, isolated-lab gateway, Tailscale subnet router |
| Windows host | 192.168.50.1 | VMware host, optional lab-side service host |
| ELASTIC01 | Tailscale network | Elasticsearch, Kibana, Fleet Server |

### Host Role Notes

**DC01** serves as the domain controller and DNS server for `c0015.lab`. It is not used as an arbitrary attack target. DC01 provides authentication telemetry (logon events, Kerberos, group policy) but is not the focus of lateral-movement experiments in the C0015 reconstruction.

**FS01** is a file-server and backup-role surrogate. It is not a true enterprise backup server. It hosts controlled SMB shares for collection and impact experiments and serves as the lateral-movement target for the WMI phase.

**Kali** has two network interfaces:
- `eth0` on VMnet2 (192.168.50.100) — lab-facing
- `eth1` on VMware NAT — outbound connectivity and Tailscale

Kali maintains the Tailscale tunnel that connects the isolated lab segment to ELASTIC01. Windows endpoints use persistent host routes to ELASTIC01 through Kali.

## Active Directory

```text
Domain:   c0015.lab
NetBIOS:  C0015
```

### Organizational Units

- `Lab-Users`
- `Lab-Computers`
- `Lab-Groups`

### Identities

| Account | Group | Purpose |
|---|---|---|
| `C0015\duc.user` | Finance | Standard user, initial victim context |
| `C0015\it.admin` | IT-Admins | Administrative account for controlled experiments |

### SMB Shares (FS01)

| Share | Local Path | Purpose |
|---|---|---|
| `\\FS01\Finance` | `C:\Shares\Finance` | Benign dummy files for collection testing |
| `\\FS01\IT` | `C:\Shares\IT` | Access-control testing |

The Finance share contains benign test files (`budget-q3.txt`, `payroll-notes.txt`) used for safe collection and impact experiments.

## Telemetry Path

```text
WS01 / FS01
  → Elastic Agent
  → Kali (192.168.50.100)
  → Tailscale tunnel
  → Fleet Server on ELASTIC01
  → Elasticsearch
  → Kibana / Elastic Security
```

Kali has a VMware NAT interface for outbound connectivity and maintains the Tailscale path to ELASTIC01. Windows endpoints use persistent host routes to the ELASTIC01 Tailscale address through Kali.

### Telemetry Stack

- Elasticsearch and Kibana on ELASTIC01
- Fleet Server on ELASTIC01
- Elastic Agent on Windows endpoints (WS01, FS01)
- Windows integration for Security and Sysmon log ingestion
- ECS-normalized fields for detection and investigation

## Endpoint Telemetry

### WS01

- **Elastic Agent** under the `C0015-Windows-Endpoints` policy, namespace `c0015`
- **Sysmon** with campaign-tuned configuration covering:
  - Process creation (Event ID 1)
  - Network connections (Event ID 3)
  - File creation (Event ID 11)
  - Registry activity (Event IDs 12, 13, 14)
  - Named pipes (Event IDs 17, 18)
  - WMI activity (Event IDs 19, 20, 21)
  - DNS queries (Event ID 22)

Future injection experiments may require additional Sysmon visibility for image/module loading and process access.

### FS01

- **Elastic Agent** under the `C0015-Windows-Endpoints` policy, namespace `c0015`
- **Windows Security auditing** for SMB/file-share access, including Event ID 5145

### DC01

- Provides authentication and group-policy telemetry
- Logon events (4624, 4625, 4672), explicit credential use, Kerberos activity

## CALDERA Integration (Planned)

Apache CALDERA will provide the orchestration and tasking layer for the Bazar and Cobalt Strike stage reconstructions:

- Campaign orchestration and adversary profiles
- Controlled agents on target endpoints
- Task scheduling and operation replay
- Task/result logging for detection validation

CALDERA serves as the controlled tasking/orchestration surrogate used to reconstruct the Cobalt Strike role. It is not Cobalt Strike; it reproduces the command-and-control workflow with observable, bounded operations.

Expected deployment: CALDERA server on Kali or the Windows host, with agents deployed to WS01 and FS01 as needed during specific campaign phases.

## Network Capture Limitations

All lab systems are on the same VMnet2 subnet. Consequences:

- Traffic between WS01 and FS01 does not traverse a router or firewall
- Network-level detection depends on host-based packet capture or Sysmon network events
- No inline network security device is available for blocking experiments
- Packet capture points must be defined per experiment

This is a known constraint documented for transparency.

## Trust and Certificate Model

Fleet Server and Elasticsearch are reached over TLS. Windows agents trust the lab CA used to sign the Fleet Server certificate. Private keys, enrollment tokens, and certificate materials are excluded from version control.

## Operational Boundary

The lab executes controlled behaviors only on owned virtual machines using benign commands, dummy data, and safe substitutes. Original Bazar/Conti malware, cracked Cobalt Strike, destructive encryption, credential theft from system processes, and uncontrolled external targeting are out of scope.

---

# Verified state & components (bổ sung 2026-09-26)

## Verified infrastructure (handoff 2026-09-26)

- **DC01** `.10`: AD DS + DNS + LDAP/Kerberos verified (`nltest /dsgetdc:c0015.lab` PASS từ WS01/FS01); OS edition `UNKNOWN`.
- **WS01** `.20`: Win10, joined; Ethernet0 = NAT (192.168.106.136, gw 192.168.106.2 — dùng tải/cập nhật), Ethernet1 = VMnet2 (DNS 192.168.50.10, không gateway, metric ưu tiên domain). **Word install: pending verification** (ODT Word-only, O365HomePremRetail).
- **FS01** `.30`: **Win10 Pro 19045**, joined. Shares: `Finance` (`C:\Shares\Finance`, Finance group = Change; `budget-q3.txt`, `payroll-notes.txt`), `IT` (`C:\Shares\IT`, IT-Admins = Change; `server-inventory.txt`). `duc.user` ∈ Finance; `it.admin` ∈ IT-Admins (không DA). it.admin local-admin trên FS01: `UNKNOWN` (gate M-1 cho WMI).
- **Elastic:** 9.5.3, Fleet `https://100.77.46.126:8220/`, policy `C0015-Windows-Endpoints`, ns `c0015`, agents WS01/FS01 Healthy, CA riêng (`fleet-ca.crt` khi enroll).
- **Sysmon live (WS01/FS01):** 15.21 / schema 4.91, binary `C:\Tools\sysmon64.exe`, config `C:\Tools\sysmon-c0015.xml`; EID 1,3,11–14,17–22 enabled, **7 và 10 disabled**; exclusions: EID3→`DC01:53`, EID11→Elastic/Edge/diag, Registry include (Run/RunOnce/Services/Classes/Environment), Registry exclude VMware Tcpip. **Live config hash `D30CD93C…` ≠ committed ≠ working-tree repo** → reconcile trong M-1 trước S2/S9 (S2/S9 cần EID 7 scoped).

## Components trong repo

| Component | Vị trí | Trạng thái |
|---|---|---|
| C2-SIM v2 (foothold beacon channel) | `scripts/c2sim_v2.py` | Implemented + 15/15 tests |
| Artifact/hash/manifest/receipt/scorecard tooling | `scripts/lab_tools.py` | Implemented + tests |
| Synthetic telemetry fixtures (replay-only) | `scripts/fixtures/` | 12 fixtures + checker |
| Run ledger schema/templates | `evidence/run-ledger/` | Schema cấm secret |
| Benign payloads (config-driven) | `payloads/` | Offline-validated (parse, impact cycle+guard, beacon↔C2-SIM) |
| Operator C2 (quyết định) | CALDERA v5 primary / Sliver tùy chọn / Havoc loại | `docs/payloads-and-c2.md` — chưa deploy |

Chi tiết blueprint/runbook: `docs/implementation-plan.md`.

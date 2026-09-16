# Architecture

## Goal

Build an isolated Windows/Active Directory environment that can generate realistic endpoint, identity, and file-share telemetry while sending logs to a separately hosted Elastic Stack.

## Systems

| Host | Role | Lab IP |
|---|---|---|
| DC01 | AD DS + DNS | 192.168.50.10 |
| WS01 | Initial Windows workstation | 192.168.50.20 |
| FS01 | Windows file server | 192.168.50.30 |
| Kali | Lab gateway / Tailscale router | 192.168.50.100 |
| ELASTIC01 | Elasticsearch + Kibana + Fleet Server | Tailscale 100.77.46.126 |

Domain: `c0015.lab`  
NetBIOS: `C0015`

## Network isolation

The Windows lab segment uses VMware VMnet2 (`192.168.50.0/24`) without a default Internet gateway. This reduces accidental exposure while still allowing controlled telemetry routing.
## Telemetry path

```text
WS01 / FS01
   -> Elastic Agent
   -> Kali (192.168.50.100)
   -> Tailscale
   -> Fleet Server / Elasticsearch on ELASTIC01
   -> Kibana / Elastic Security
```

Kali has a second VMware NAT interface for outbound connectivity and maintains the Tailscale path to ELASTIC01. Windows endpoints use persistent host routes to `100.77.46.126/32` through Kali.

## Endpoint telemetry

WS01 and FS01 use Elastic Agent under the `C0015-Windows-Endpoints` policy and namespace `c0015`.

WS01 additionally uses Sysmon for detailed process, network, file, registry, WMI, named-pipe, and DNS telemetry.

FS01 provides Windows Security auditing for SMB/file-share access, including Event ID 5145.

## Elastic components

- Elasticsearch 9.5.3
- Kibana 9.5.3
- Fleet Server on ELASTIC01
- Elastic Agent on Windows endpoints
- Windows integration for Security and Sysmon logs
- ECS-normalized fields for detection and investigation
## Active Directory foundation

Organizational units:
- `Lab-Users`
- `Lab-Computers`
- `Lab-Groups`

Test identities:
- `C0015\duc.user` - member of Finance
- `C0015\it.admin` - member of IT-Admins

FS01 shares:
- `\\FS01\Finance`
- `\\FS01\IT`

The Finance share contains benign dummy files such as `budget-q3.txt` and `payroll-notes.txt` for safe collection testing.

## Trust and certificate model

Fleet and Elasticsearch are reached over TLS. Windows agents trust the lab CA used to sign the Fleet Server certificate. Private keys and enrollment tokens are excluded from version control.

## Operational boundary

The lab emulates ATT&CK behaviors only on owned virtual machines and benign data. Real Conti/Bazar malware, credential theft, destructive encryption, and uncontrolled external targeting are explicitly out of scope.

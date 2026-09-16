# C0015 Conti Detection Lab - Lab Journal

## 2026-09-12 - Initial Telemetry Pipeline Validation

### Objective
Validate the end-to-end telemetry pipeline from a Windows endpoint to the Elastic Stack before beginning C0015 attack emulation.

### Lab Architecture

- WS01: Windows 10 workstation / initial victim
  - Lab IP: 192.168.50.20
  - Elastic Agent installed
  - Sysmon installed
- Kali:
  - Lab IP: 192.168.50.100
  - VMware NAT interface: 192.168.106.133
  - Tailscale subnet router / gateway for the isolated Windows lab
- ELASTIC01:
  - Ubuntu 24.04
  - Elasticsearch 9.5.3
  - Kibana 9.5.3
  - Fleet Server
  - Hosted in Azure
  - Tailscale IP: 100.77.46.126

### Network Design

WS01 does not have a general Internet default gateway.

Telemetry path:

WS01
→ Kali (192.168.50.100)
→ Tailscale
→ ELASTIC01 (100.77.46.126)
→ Elasticsearch
→ Kibana

Fleet Server:
- TCP 8220

Elasticsearch:
- TCP 9200

### Validation

Elastic Agent successfully enrolled into the `C0015-Windows-Endpoints` Fleet policy.

Windows Security events were successfully ingested into the `c0015` namespace.

Validated fields included:

- `host.name`
- `host.hostname`
- `agent.name`
- `event.dataset`
- `event.code`

Observed Windows Security event IDs included:

- 4624
- 4672
- 5379

Sysmon was installed and the `Microsoft-Windows-Sysmon/Operational` event log was validated locally.

Sysmon Event ID 1 (Process Create) was then validated through the Elastic ingestion pipeline.

### Troubleshooting Finding - VMware NAT Failure

During telemetry validation, Elastic Agent lost connectivity to both:

- Fleet Server TCP/8220
- Elasticsearch TCP/9200

WS01 could still reach Kali at `192.168.50.100`, and its persistent route to ELASTIC01 remained correct.

Investigation showed that Kali had lost its VMware NAT interface:

- `eth0`: UP
- `eth1`: DOWN
- Default route: missing
- Tailscale: `NoState`

Root cause:

`VMware NAT Service` on the Windows host was stopped.

After restarting the VMware NAT Service:

- Kali `eth1` recovered `192.168.106.133/24`
- Default route via `192.168.106.2` returned
- Tailscale connectivity recovered
- WS01 could reach TCP/8220 and TCP/9200
- Elastic Agent automatically recovered without reinstallation

### Key Lesson

A degraded SIEM agent does not necessarily indicate an agent or integration failure.

Troubleshooting should follow the telemetry path layer by layer:

Endpoint
→ Gateway
→ Overlay network
→ Fleet Server / Elasticsearch
→ Agent
→ Integration

The failure was isolated before changing the Elastic Agent configuration, preventing unnecessary reinstallation or policy changes.

### Sysmon Telemetry Validation

The initial Sysmon configuration successfully produced the expected telemetry:

- Event ID 1 - Process Create
- Event ID 3 - Network Connection
- Event ID 11 - File Create
- Event ID 22 - DNS Query

The initial visibility-first configuration also generated substantial event volume, particularly for network, file, and registry activity.

This demonstrated that collecting all available Sysmon telemetry is operationally noisy and motivated a second configuration focused on campaign-relevant telemetry and source-side filtering.

### Registry telemetry tuning validation

The initial Sysmon registry configuration generated repetitive benign events from
`C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` accessing:

`HKLM\System\CurrentControlSet\Services\Tcpip\Parameters`

A targeted exclusion was added for this specific process/path combination rather
than excluding the entire Services registry tree.

Validation showed that the VMware Tools noise disappeared while security-relevant
registry telemetry remained intact. A controlled modification of:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

successfully generated Sysmon Event ID 13.

Result: benign noise was reduced without losing visibility into persistence-relevant
registry activity.## 2026-09-14 - Active Directory and File Server Foundation

DC01 was promoted to a domain controller for `c0015.lab` and configured as the lab DNS server.

Created test identities and groups:
- `duc.user` -> Finance
- `it.admin` -> IT-Admins

WS01 and FS01 were joined to the domain. Elastic telemetry confirmed the transition from local identities to domain fields such as `user.domain = C0015`.

FS01 was configured with two SMB shares:
- `Finance`
- `IT`

Benign dummy files were created for controlled access testing. From WS01, `duc.user` could enumerate and access the Finance share while access to the IT share was denied as intended.
## 2026-09-15 - Discovery and SMB Collection Detection Milestone

Validated the following behaviors on WS01:
- T1057 Process Discovery
- T1069.002 Domain Groups Discovery
- T1482 Domain Trust Discovery
- T1135 Network Share Discovery

FS01 file-share auditing was enabled for the Finance test data. Event ID 5145 successfully recorded remote access to `budget-q3.txt` from WS01 by `C0015\duc.user`.

Elastic Agent was installed on FS01 and enrolled into Fleet after resolving route, CA trust, token, and local daemon-state issues. Security Event ID 5145 then became centrally searchable in Elastic.

Five low-severity atomic rules were created as building blocks. A final ES|QL rule correlated discovery and collection activity across WS01 and FS01.

Final result:
- rule: `Suspicious Discovery and Network Share Collection Chain`
- severity: Medium
- risk score: 60
- ATT&CK mapped to Discovery and Collection
- end-to-end validation: PASS

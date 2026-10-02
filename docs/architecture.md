# Lab architecture

This document describes the implementation represented by the retained runs
**RUN-20261002-05 through -09**. The [latest report](../reports/reference-run-20261002-09.md)
and [ledger](../evidence/runs/RUN-20261002-09/RUN-20261002-09.json) provide run-specific
evidence. Repository configuration is not a fresh inspection of running VMs.

## Hosts and network roles

| Host | Lab address | Role |
|---|---|---|
| Windows operator host | 192.168.50.1 | VMware control, C2-SIM, HTTP staging, WebDAV sink, evidence capture |
| DC01 | 192.168.50.10 | AD DS and DNS for `c0015.lab`; monitored domain controller |
| WS01 | 192.168.50.20 | Windows 10 beachhead, Word entry, discovery and operator/transfer processes |
| FS01 | 192.168.50.30 | Windows 10 Pro file server, WMI target, RDP endpoint, impact corpus |
| Kali | 192.168.50.100 | Auxiliary tooling/build role; not the active operator C2 in these runs |
| ELASTIC01 | 100.77.46.126 via Tailscale | Elasticsearch/Kibana/Fleet backend, version 9.5.3 |

The internal lab segment is **192.168.50.0/24**. WS01/FS01 also have NAT connectivity;
their NAT addresses are DHCP state, not stable correlation keys. Domain-facing DNS
uses DC01. Keep interface roles separate when interpreting source addresses.
DC01 supplies directory services and DNS; it is not merely a telemetry-only machine.

## Directory services and identity

The domain is `c0015.lab`, NetBIOS name **C0015**. The document entry runs as
`C0015\duc.user` (Finance). Operator actions use pre-provisioned `C0015\it.admin`;
the recorded setup assigns local administrator rights on WS01 and FS01. Possession
of this lab account is not evidence of credential theft in the original campaign.

FS01 exposes Finance and IT data folders under `C:\Shares\`. The recorded share
permissions give Domain Admins Full access and the respective Finance/IT-Admins
groups Change access. Share ACLs alone do not establish effective NTFS access.
The retained collection reads those folders through **C$**, then stages data under
`C:\C0015\collect`; it does not use the ordinary Finance/IT share names for that path.

## Simulator and data-transfer services

| Service | Operator-host endpoint | Function |
|---|---|---|
| HTTP staging | :8000 | Serves compiled bootstrap/tool artifacts |
| C2-SIM | :8080 | Registers sessions, queues tasks, accepts results, writes registration receipts |
| rclone WebDAV sink | :9001 | Receives two rounds of dummy collection data |

C2-SIM implements both initial callbacks and subsequent operator tasking. CALDERA,
Sliver and Havoc appeared in earlier option analysis; they are not deployed components
of the retained reference runs. AnyDesk vendor-relay traffic is separate from C2-SIM
and was not used as the simulator's operator channel.

## Sysmon profiles

Recorded Sysmon: **15.21**, schema **4.91**. Both profiles are committed:

| Profile | Scope |
|---|---|
| [BALANCED](../configs/sysmon/sysmon-c0015-balanced.xml) | Scoped ImageLoad and ProcessAccess; targeted registry capture and background exclusions |
| [CAPTURE](../configs/sysmon/sysmon-c0015-capture.xml) | Broader capture for investigation; higher expected volume |

Both use SHA-256 and IMPHASH. `DnsLookup=false` disables reverse lookups; it does
not disable **E22 DNS Query**. BALANCED includes E7 for selected loaders/paths and
E10 for selected access targets, including LSASS. It is not an unfiltered capture of
all module loads or process accesses. The XML also contains path/process predicates
and a DC DNS-connection exclusion; it is not free of lab-specific filters.

Event families configured across the profiles include E1/E2/E3/E5/E6/E7/E8/E9/E10/E11,
E12–E18, E19–E22, E25/E26/E29. Empty include rules disable E23/E24/E27/E28;
E26 records deletions without the E23 archive behavior. An enabled event family does
not imply it occurred during S1–S3 or any other particular stage.

The retained WMI-pivot evidence has E7 hashes in **`file.hash.sha256` (ECS)**.
The previous “unpopulated” conclusion came from checking the wrong field. The current
verifier checks the expected DLL hash. Old September configuration hashes and disabled
E7/E10 observations are historical snapshots, not current baseline claims.

## Windows auditing and ingestion

| Source/subcategory | Required signal or purpose | Interpretation |
|---|---|---|
| Sysmon Operational | E1 ancestry, E3 connections, E7 module loads, E10 access, E11 writes | Verify per-event entity and mapped fields |
| Security / Logon | 4624/4625/4648 where the authentication path generates them | Type 3 is network; Type 10 is RemoteInteractive; Type 4 is batch |
| Security / Special Logon | 4672 | Assigned special privileges; not proof of group membership |
| Security / Detailed File Share | 5145 | Share access check; not proof of complete content transfer |
| Security / Logoff | 4634/4647 where generated | Distinguish logoff from disconnect |
| Security / Other Logon/Logoff Events | 4778/4779 where generated | Reconnect/disconnect; not separately verified in the retained RDP lifecycles |

Additional sources such as PowerShell 4104, WMI-Activity, Defender Operational, object
access 4663 with SACLs, and network packet capture can enrich investigation. Their
availability must be checked independently; this document does not claim complete
ingestion or run coverage for every recommended source.

Endpoint Elastic Agents read event channels and send events to their configured
**Elasticsearch output**. **Fleet Server (:8220) manages enrollment, policy, and
check-ins**; it is not the telemetry relay for all event documents. Kibana provides
Discover, rule management, and alert investigation.

Recorded policy: `C0015-Windows-Endpoints`; namespace: `c0015`.
The principal data-stream patterns are:

- `logs-windows.sysmon_operational-c0015*`
- `logs-system.security-c0015*`

Security is in **system.security**, not an assumed windows.security dataset.
Fleet Healthy verifies agent control-plane health, not ingestion of every source.

## Verification and trust

Distinguish **CONFIGURED**, **LOCAL OBSERVED**, and **INGEST VERIFIED**. Match local
and ingested events by host, channel, RecordID and time where those records are
available. Preserve raw event data and ECS fields when provided by the integration.
Record event time separately from ingestion/alert creation time.

Fleet uses the lab CA (`fleet-ca.crt`) for TLS. A Windows curl trust or revocation
failure does not by itself diagnose the Elastic Agent's CA configuration. The
acceptance script's lab TLS behavior is separate from Fleet enrollment trust.
Credentials remain runtime inputs and are not required in documentation or evidence.

Campaign execution is **S1–S14**. Post-run verification, recovery and cleanup are
separate activities. The bounded impact corpus resides on FS01, outside system and
evidence paths; the retained recovery claim is content/hash equality, not complete
enterprise recovery or independently verified ACL restoration.

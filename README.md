# C0015 Detection Lab

> **Repository language: English.** All repository content (docs, code comments, commit
> messages, artifacts) is written in English; conversational notes in issues/PRs may use
> the author's language.

Evidence-driven reconstruction of [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/)
(Conti/Bazar intrusion, DFIR Report *CONTInuing the Bazar Ransomware Story*, 2021-11-29) for detection
engineering and incident-response training on an owned homelab. The lab relies on real Windows, Active
Directory, network, and file telemetry, lab-safe surrogates, and explicit artifact handoffs between stages —
never a marker-only "PASS".

## What C0015 Is

C0015 is the MITRE ATT&CK campaign documenting the Conti/Bazar intrusion chain described in the DFIR Report:
a Word macro drops an HTA bootstrap, the HTA decodes base64 payloads and downloads a DLL masquerading as a
JPEG that is loaded through regsvr32, an initial C2 beacon establishes a foothold, the operator performs
discovery and lateral movement over SMB and WMI with explicit credentials, collected files are staged and
transferred, movement continues over RDP and remote-access tooling, and the intrusion ends in a bounded
ransomware-style impact. The lab replays this chain as fifteen labelled stages (S1-S15) with artifact handoffs
between stages:

```text
S1  Word macro
  -> S2  HTA (VBS + JS + base64) -> DLL (.jpg) loaded via regsvr32
  -> S3  Session 1 (C2-SIM v3 dynamic tasking, public-IP mock)
  -> S4  Discovery (exact DFIR commands)
  -> S5  found_shares artifact
  -> S6  Orchestrator target decision
  -> S7  Auth controls (it.admin explicit credential)
  -> S8  Tool handoff (C$ SMB) + WMI remote process (rundll32)
  -> S9  Session 2 (server-side receipt)
  -> S10 Collection / staging (manifest + hash)
  -> S11a Transfer r1
  -> S12 RDP
  -> S11b Transfer r2
  -> S13 AnyDesk-like channel + LSASS telemetry study
  -> S14 Bounded impact + restore / verify
  -> S15 End-to-end engineering + investigation runs (ground truth hidden)
```

C2 channels (researched and install-verified): **C2-SIM v3** (foothold beacon; operator-entered benign commands via
dynamic tasking), **Apache CALDERA v5** (operator
orchestration, primary), Sliver optional under strict conditions, Havoc excluded. Details and the AD three-VM
assessment are in `docs/payloads-and-c2.md`.

Current status: design is complete and all offline components are implemented — the 15 offline unit tests pass
and the benign payloads have been validated offline (parse, impact cycle with guard, beacon-to-C2-SIM over
localhost). No live lab run has been completed yet: the chain is not end-to-end until a single continuous run
produces handoff evidence for every stage.

## Lab Architecture

Host-only VMnet2 `192.168.50.0/24`, DHCP off. Domain `c0015.lab` / NetBIOS `C0015`.

| Host | Role | Address |
|---|---|---|
| DC01 | AD DS + DNS (the campaign never touches the DC — telemetry only) | 192.168.50.10 |
| WS01 | First victim (Windows 10, `duc.user`) | 192.168.50.20 |
| FS01 | File + backup-server role (Windows 10 Pro 19045; shares Finance -> `duc.user`, IT -> `it.admin`) | 192.168.50.30 |
| Kali | Operator / C2 host (planned) | 192.168.50.100 |
| ELASTIC01 | Elastic 9.5.3 / Kibana / Fleet (`https://100.77.46.126:8220`, policy `C0015-Windows-Endpoints`, namespace `c0015`) | Tailscale |

Windows endpoints run the Elastic Agent (healthy) with Sysmon 15.21 (schema 4.91). The live Sysmon
configuration (hash `D30CD93C...`) is an unverified third variant with E7/E10 disabled. Two profiles are
committed under `configs/sysmon/`: the routine **BALANCED** profile (`sysmon-c0015-balanced.xml`, scoped
E7/E10/Registry to keep volume low) and the **CAPTURE** profile (`sysmon-c0015-capture.xml`, unfiltered
E7/E10/Registry for bounded observation sessions). Reconcile the live file with these before the S2/S9
observation runs (E7 required).

## Repository Structure

```text
C0015-Conti-Detection-Lab/
├── README.md
├── configs/sysmon/          # Sysmon profiles: BALANCED (routine, scoped) + CAPTURE (observation, broad)
├── detections/              # Atomic KQL, correlation ES|QL, EQL prototypes
├── docs/                    # Blueprint, narrative, fidelity, correlation, payload/C2 documents
├── evidence/run-ledger/     # Run ledger schema + templates
├── payloads/                # Benign config-driven payloads (docm/hta/dll/beacon/impact + config)
└── scripts/                 # c2sim_v2.py, lab_tools.py, tests/, fixtures/ (synthetic replay)
```

## Documentation

- [Implementation Plan](docs/implementation-plan.md) — single blueprint, stages, gates, milestones, operator runbook
- [Attack-Chain Plan](docs/attack-chain-plan.md) — narrative, historical fidelity, canonical phase map 0-15
- [Correlation Architecture](docs/correlation-architecture.md) — detection correlation design
- [Payloads & C2](docs/payloads-and-c2.md) — C2-SIM v3 design, CALDERA/Sliver/Havoc research, AD three-VM verdict
- [Architecture](docs/architecture.md) — lab architecture

## Evidence & Fidelity

Every claim in the repository is labelled so that historical facts are never confused with lab observations.
Labels: `[OBSERVED-C0015]`, `[INFERRED-C0015]`, `[UNKNOWN-C0015]` (historical facts), `[LAB-SURROGATE]`,
`[SUPPLEMENTAL-LAB-TECHNIQUE]`, `[NOT-VERIFIED-IN-REPO]`. Status vocabulary: `VERIFIED IN REPO`, `ARTIFACT
VERIFIED`, `NARRATIVE ONLY`, `NOT VERIFIED`, `NOT RUN`, `PARTIAL`, `SENSOR GAP`, `DETECTED`, `CONTRADICTED`.
Correlation tiers: `DIRECT EVENT LINK`, `SUPPORTED HANDOFF`, `CONTEXTUAL ONLY`, `UNPROVEN`, `CONTRADICTED`.
Every historical gap is replaced by an executable lab technique with a label — no chain step stays unknown.

## Safety Boundaries

Owned VMs only. No real Bazar, Conti, or Cobalt Strike malware; no injection into Winlogon, svchost, LSASS,
or other system processes; no credential dumping; no public C2 or cloud exfiltration (internal allowlist sink
only); no general-purpose encryptor or propagation (bounded corpus with restore); no secrets in the repository.

## Quick Start (Offline)

```powershell
python scripts/tests/test_offline.py            # 15/15 offline unit tests
python scripts/c2sim_v2.py --ip 127.0.0.1 --port 8080 --ledger evidence/run-ledger --log c2sim.log
python scripts/lab_tools.py fixture-check scripts/fixtures
# Payload build/run instructions and the code-to-technique map: payloads/README.md
```
# C0015 Detection Lab

Evidence-driven reconstruction of [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/)
(Conti/Bazar intrusion, DFIR Report *CONTInuing the Bazar Ransomware Story*, 2021-11-29) for detection
engineering and IR training on an owned homelab. Real Windows/AD/network/file telemetry, lab-safe surrogates,
explicit handoffs between stages — never marker-only "PASS".

## Status at a glance (2026-09-26)

| Layer | State |
|---|---|
| Attack-chain blueprint S1–S15 (single `run_id`, artifact handoffs) | ✅ design done — `docs/implementation-plan.md` |
| Historical fidelity + canonical phase map 0–15 + OLD→NEW | ✅ — `docs/attack-chain-plan.md` §10–13 |
| Evidence ledger (repo-verified vs narrative-only) | ✅ — `docs/evidence-matrix-v2.md` |
| Offline components (run-ledger schema, C2-SIM v2, artifact/hash/receipt/scorecard, fixtures) | ✅ implemented, **15/15 offline tests OK** |
| Benign payloads (macro / HTA / DLL / beacon / bounded impact), config-driven | ✅ implemented, offline-validated (parse, impact cycle + guard, beacon↔C2-SIM localhost) |
| Live lab runs (S1–S15) | ⏳ **NOT RUN** — chain is **not end-to-end** until one continuous run has handoff evidence for every stage |
| Legacy claims post-2026-09-19 (auth bridge, WMI canary, DET-008, T1018/1016) | ⚠️ `NOT VERIFIED IN REPO` — kept, not promoted to PASS |

## The chain

```text
S1 Word macro → S2 HTA (VBS+JS+base64) → DLL(.jpg) → regsvr32 → S3 session 1 (C2-SIM, public-IP mock)
→ S4 discovery (exact DFIR commands) → S5 found_shares artifact → S6 orchestrator picks target
→ S7 auth controls (it.admin, explicit credential) → S8 tool handoff (C$) + WMI remote process (rundll32)
→ S9 session 2 (server-side receipt) → S10 collection/staging (manifest+hash)
→ S11a transfer r1 → S12 RDP → S11b transfer r2 → S13 AnyDesk-like + LSASS telemetry study
→ S14 bounded impact + restore/verify → S15 E2E (engineering + investigation, ground truth hidden)
```

C2 channels (researched, install-verified): **C2-SIM v2** (foothold beacon) · **Apache CALDERA v5** (operator
orchestration, primary) · Sliver optional under strict conditions · Havoc excluded. Details + AD 3-VM assessment:
`docs/payloads-and-c2.md`.

## Lab architecture (verified 2026-09-26)

VMnet2 `192.168.50.0/24`, host-only, DHCP off. Domain `c0015.lab` / NetBIOS `C0015`.

| Host | Role | Address |
|---|---|---|
| DC01 | AD DS + DNS (campaign never touches DC — telemetry only) | 192.168.50.10 |
| WS01 | First victim (Win10, Word pending verify, `duc.user`) | 192.168.50.20 |
| FS01 | File + backup-server role (Win10 Pro 19045; shares Finance→duc.user, IT→it.admin) | 192.168.50.30 |
| Kali | Operator / C2 host (planned) | 192.168.50.100 |
| ELASTIC01 | Elastic 9.5.3 / Kibana / Fleet (`https://100.77.46.126:8220`, policy `C0015-Windows-Endpoints`, ns `c0015`) | Tailscale |

Windows endpoints: Elastic Agent healthy; Sysmon 15.21 (schema 4.91) — live baseline EID 1,3,11–14,17–22 on,
**7/10 off** (live config hash ≠ any repo version — reconcile in M-1 before S2/S9).

## Repository structure

```text
C0015-Conti-Detection-Lab/
├── README.md
├── docs/                       # blueprint, narrative, evidence, contracts
├── detections/                 # atomic KQL · correlations ES|QL · EQL prototypes
├── configs/sysmon/             # Sysmon config (committed baseline; working-tree variant uncommitted — M-1 decision)
├── scripts/                    # c2sim_v2.py, lab_tools.py, tests/, fixtures/ (synthetic replay only)
├── payloads/                   # benign config-driven payloads (docm/hta/dll/beacon/impact + config template)
└── evidence/                   # phase1-evidence-index.md, run-ledger/ (schema + templates)
```

## Documentation

- [Attack-Chain Blueprint & Runbook](docs/implementation-plan.md) — single blueprint, stages, gates, milestones
- [Attack-Chain Plan (narrative + fidelity + phase map)](docs/attack-chain-plan.md) — historical vs surrogate; canonical 0–15
- [Evidence Matrix v2](docs/evidence-matrix-v2.md) — evidence ledger
- [Phase Handoff & Artifact Contracts](docs/handoff-contracts.md)
- [Correlation Architecture](docs/correlation-architecture.md)
- [Payloads & C2 Decisions](docs/payloads-and-c2.md) — C2-SIM v2 design, CALDERA/Sliver/Havoc research, AD 3-VM verdict
- [Architecture](docs/architecture.md) · [Detection Engineering](docs/detection-engineering.md) ·
  [Investigation](docs/investigation.md) · [Experiments](docs/experiments.md) · [Lab Journal](docs/lab-journal.md) ·
  [Original Build Plan 0–11](docs/plan.md) (historical)

## Evidence & fidelity

Labels: `[OBSERVED-C0015]` · `[INFERRED-C0015]` · `[UNKNOWN-C0015]` (historical facts) · `[LAB-SURROGATE]` ·
`[SUPPLEMENTAL-LAB-TECHNIQUE]` · `[NOT-VERIFIED-IN-REPO]`. Status vocabulary: `VERIFIED IN REPO`, `ARTIFACT
VERIFIED`, `NARRATIVE ONLY`, `NOT VERIFIED`, `NOT RUN`, `PARTIAL`, `SENSOR GAP`, `DETECTED`, `CONTRADICTED`.
Every historical gap is replaced by an executable lab technique with a label — no chain step stays "unknown".
Correlation tiers: `DIRECT EVENT LINK` / `SUPPORTED HANDOFF` / `CONTEXTUAL ONLY` / `UNPROVEN` / `CONTRADICTED`.

## Safety boundaries

Owned VMs only. No real Bazar/Conti/Cobalt Strike, no injection into Winlogon/svchost/LSASS/system processes, no
credential dumping, no public C2 or cloud exfiltration (internal allowlist sink), no general-purpose encryptor or
propagation (bounded corpus + restore), no secrets in the repo.

## Quick start (offline)

```powershell
python scripts/tests/test_offline.py            # 15/15 offline tests
python scripts/c2sim_v2.py --ip 127.0.0.1 --port 8080 --ledger evidence/run-ledger --log c2sim.log
python scripts/lab_tools.py fixture-check scripts/fixtures
# payloads build/run + code→technique map: payloads/README.md
```

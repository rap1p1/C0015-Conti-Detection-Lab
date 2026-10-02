# docs — Canonical technical records

Flat set of design/analysis documents that span the phases; phase-specific plans
and run records live in `../phases/<phase>/`.

| Document | Contents |
|---|---|
| [attack-chain-plan.md](attack-chain-plan.md) | The canonical S1-S15 chain: historical behavior per stage (`[OBSERVED-C0015]`), lab fidelity, telemetry/evidence rules, safety boundaries. |
| [attack-runbook.md](attack-runbook.md) | Operator runbook: exact commands and expected evidence per stage (pre-run state + full walkthrough). |
| [architecture.md](architecture.md) | Lab topology (VMs, VMnet2, host/guest channels), Elastic/Fleet ingestion, C2-SIM + HTTP servers. |
| [correlation-architecture.md](correlation-architecture.md) | Detection correlation design: event joins (entity/logon-id/window), index layout, sweep mechanics. |
| [telemetry-comparison-c0015-vs-lab.md](telemetry-comparison-c0015-vs-lab.md) | Event-level parity table: what the real intrusion produced vs what the lab emits (Sysmon/Security). |
| [payloads-and-c2.md](payloads-and-c2.md) | Payload design notes and C2-SIM behavior (tasking, sessions, receipts). |

Traceability: every stage in `attack-chain-plan.md` maps to a rule in
`../detections/README.md` and to the per-phase folder in `../phases/`.
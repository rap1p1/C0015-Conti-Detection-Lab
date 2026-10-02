# Technical documentation

Read the latest [reference report](../reports/reference-run-20261002-09.md) alongside its
[ledger](../evidence/runs/RUN-20261002-09/RUN-20261002-09.json). Run records describe what
was observed; design notes describe intent. A later replay does not retroactively validate an older experiment.

| Document | Purpose |
|---|---|
| [Architecture](architecture.md) | Hosts, networks, directory services, telemetry collection, and backend paths |
| [Campaign mapping](attack-chain-plan.md) | Historical sources, current S1–S14 stage map, and fidelity distinctions |
| [Runbook](attack-runbook.md) | Machine-specific procedure and expected evidence; command templates require runtime values |
| [Correlation architecture](correlation-architecture.md) | Entity and logon joins, evidence tiers, and analyst correlation guidance |
| [Telemetry comparison](telemetry-comparison-c0015-vs-lab.md) | Campaign behavior versus evidence in the retained runs |
| [Payloads and C2](payloads-and-c2.md) | Implemented components, simulator endpoints, and control model |

The campaign ends at **S14**. **S15** in historical ledgers is post-run validation.
The [rule catalogue](../detections/README.md) maps detectable behaviors to rules;
not every stage has a dedicated rule. S6 is an orchestration decision.

The phase folders retain investigation history. Their design documents are explicitly
marked as historical where the implementation has superseded the proposed procedure.

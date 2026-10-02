# Infrastructure and verification tools

| Component | Purpose |
|---|---|
| [c2sim.py](c2sim.py) | HTTP simulator: registration, task queue, operator commands, results, and session receipts |
| [c2sim_guard.py](c2sim_guard.py) | Simulator watchdog; launch/stop harness coordinates its lifecycle |
| [lab_tools.py](lab_tools.py) | Artifact creation/checking, manifests, receipts, scorecards, and fixture checks |
| [runbooks/](runbooks/) | Ordered discovery command data; separate from the simulator's default task stream |
| [fixtures/](fixtures/) | 11 synthetic JSON fixtures; not real run evidence |
| [tests/](tests/) | 20 offline component tests; no EQL engine or Elastic integration test |
| [verify/verify_run_evidence.py](verify/verify_run_evidence.py) | Earlier telemetry verifier; consult its run/window settings |
| [verify/verify_final_phases.py](verify/verify_final_phases.py) | Run-specific acceptance assertions against Elastic, runtime log, and committed artifacts |
| [verify/fetch_evidence_ids.py](verify/fetch_evidence_ids.py) | Event-reference collection for defined windows |
| [rules/gen_rules_ndjson.ps1](rules/gen_rules_ndjson.ps1) | Query-to-NDJSON builder with metadata and export validation |
| [diag/wmi_rundll32_diag.ps1](diag/wmi_rundll32_diag.ps1) | Historical WMI transport diagnostic |

Run offline component tests from the repository root:

```bash
python -m unittest discover -s scripts/tests
```

Acceptance is a separate operation requiring retained Elastic telemetry and runtime
inputs. Supported run IDs are defined in the verifier. Some checks are informational,
including the 4634 session-end lookup; they are not all failure gates. R19/R23 checks
can use archived ledger references when live alert documents have been cleared.
See [evidence documentation](../evidence/README.md) before interpreting `ACCEPTED`.

## Simulator interface

Implemented endpoints include **POST `/session/register`**, **GET `/task/next`**,
**POST `/result`**, **POST `/cmd`**, **POST `/runbook`**, and GET `/sessions`,
`/results`, `/last`. The old `/register` and `/poll` names are not current routes.
Full endpoint semantics are in [payloads-and-c2.md](../docs/payloads-and-c2.md).

Operator commands are dynamic. Size checks and a limited credential-string filter
do not provide a benign-command allowlist or comprehensive secret detection.
Sessions/results are in memory; a server restart does not preserve them.

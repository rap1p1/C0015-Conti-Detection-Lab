# scripts — Infrastructure & tools

| Script | Purpose | Key technical points |
|---|---|---|
| `c2sim.py` | C2 simulator (HTTP :8080) | endpoints: `/register`, `/poll`, `/cmd`, `/runbook`, `/sessions`, `/results`; sessions/tasks in memory; beacon polling loop with jitter; runbook batches executed as ordered tasks; results capped (`result_cap_bytes`) |
| `c2sim_guard.py` | watchdog for C2-SIM | relaunches c2sim on crash/exit (used by `launch_servers.ps1 -Stop` to tear down together) |
| `lab_tools.py` | evidence toolkit | `artifact-new` / `artifact-check` (sha256'd artifact files), `manifest-new` (corpus manifest with per-file hash/size), `receipt-check` (hash equality vs manifest), `score` (coverage scorecard), `fixture-check` (offline fixture validation) |
| `runbooks/c0015-phase2.json` | S4-S5 discovery batch | the exact `[OBSERVED-C0015]` command set: `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all`, `whoami`, `tasklist /s`, `ping`, `systeminfo`, `Get-SmbShare` |
| `fixtures/` | offline event fixtures | E1/E3/E7/E10/E11/S4624/S4625/S5145 samples + fixture README, replayable for rule tests |
| `tests/test_offline.py` | offline test suite | runs rule queries against the fixtures without Elastic (`python -m unittest`) |
| `scripts/verify/verify_run_evidence.py` | run telemetry verifier | per-stage Elastic queries by window (S1-S9) |
| `scripts/verify/verify_final_phases.py` | final-campaign verifier | per-stage Elastic queries for S1-S15 (plain `urllib`, unverified TLS for the lab ES) |
| `scripts/rules/gen_rules_ndjson.ps1` | rule builder | deterministic rule_id (SHA-256 of name), suppression map, metadata; **loader list must include every rule file** |
| `scripts/diag/wmi_rundll32_diag.ps1` | G2 diagnostic | SWbemLocator COM transport probe for the WMI→rundll32 pivot |

## Offline tests

```
python -m unittest discover -s scripts/tests
```

## Runbooks

`runbooks/c0015-phase2.json` is the canonical discovery runbook; queue it on a session
with `POST /runbook?session=<token>&name=c0015-phase2`.





## Control model

The simulator accepts operator-issued commands (`/cmd`) and runbook batches; benign-execution
guarantees are procedural (operator conventions, staged payloads, scheduled-task delegation), not
code-enforced allowlists. Task-type allowlists inside runbooks are a convention, not an enforcement
boundary.

# Session beacon

[c0015_beacon.ps1](c0015_beacon.ps1) is the PowerShell task-loop client for C2-SIM,
used for WS01 session 1 and FS01 session 2. It is a simulator component, not a
BazarLoader or Cobalt Strike binary.

## Protocol and state

- POST `/session/register`, GET `/task/next?session=<token>`, POST `/result`.
- Queued operator/runbook commands arrive as OP-CMD tasks and execute through CMD;
  named default tasks are a separate stream.
- Token comes from the configured environment/file mechanism or is generated at
  runtime. The registration response supplies the canonical token on reuse.
- The current loop runs until stopped; `-Once` executes one iteration.
  **`loop_count` is advisory**, not an enforced iteration limit.
- Result size is capped by configuration; output read-back uses the simulator's
  in-memory `/results` and `/last` endpoints.

Configuration sections cover `[c2sim]`, `[beacon]`, and `[public_ip]`; the local INI
helper is `Get-IniValue`. An elevated WS01 handoff and an FS01 second session are
different process/host contexts even if both use a phase7-named configuration.

## Existing invocation template

```
powershell -NoProfile -ExecutionPolicy Bypass -File c0015_beacon.ps1 -Config C:\C0015\config.ini
```

Telemetry includes E1 execution, E3 attributed connections, and E11 token/marker
writes where captured. HTTP task/result contents are not available in Sysmon E3.
For actual entities, tokens and relaunches, inspect the per-run ledger.

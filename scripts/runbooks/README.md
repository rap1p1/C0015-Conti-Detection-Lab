# Operator command batches

[c0015-phase2.json](c0015-phase2.json) holds **11 ordered entries** with `cmd` and optional
`pause` fields. It includes campaign-inspired discovery and supplemental lab probes;
it is not an exact transcript of every historical command.

C2-SIM queues the entries through POST `/runbook?session=<token>&name=c0015-phase2`.
The beacon receives them as **OP-CMD** tasks; they are not individual `T-<name>` task
types. Outputs can be read through `/results` or `/last` while the server is running.

The JSON description retains an earlier real-Mimikatz design. The retained reference
runs document the compiled **LSASS-access surrogate** instead. The discovery JSON
contains no credential-acquisition procedure; use the current [campaign mapping](../../docs/attack-chain-plan.md)
and [reports](../../reports/) to distinguish implemented behavior from older intent.

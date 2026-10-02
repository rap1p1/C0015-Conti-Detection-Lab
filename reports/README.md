# Reference-run reports

Reports separate campaign execution, detection evaluation, and recovery. Timestamps
refer to source events unless a row explicitly identifies alert creation time.

| Report | Purpose |
|---|---|
| [RUN-20261002-09](reference-run-20261002-09.md) | Latest replay; fixed-target S6 decision and RDP logon-to-logoff evidence |
| [RUN-20261002-08](reference-run-20261002-08.md) | Replay with rebuilt event provenance and C$ collection evidence |
| [RUN-20261002-07](reference-run-20261002-07.md) | Rule-tuning reference; live R22/R23/R24 coverage and measured alert volume |
| [RUN-20261002-06](reference-run-20261002-06.md) | Bidirectional impact verification; R19 positive; earlier rule suite |
| [RUN-20261002-05](reference-run-20261002-05.md) | First retained campaign run; one-directional impact comparison; T10 predates R19 coverage |

**RUN-20261002-09** is the latest reference. **RUN-20261002-07** is the rule-tuning
reference. Each report links to its [ledger and artifacts](../evidence/runs/).
Historical counts reflect the rule configuration and measurement method at that run,
not the current 24-rule suite. Stored alert documents, suppressed matches, and unique
entities/sequences are different measurements.

# Run records

Each directory contains `RUN-<id>.json` and that run's artifacts.
The shared [RUN-schema.json](RUN-schema.json) defines ledger structure.

| Run directory | Purpose |
|---|---|
| [RUN-20261002-09](RUN-20261002-09/) | Latest replay; fixed-target S6 decision and RDP logon-to-logoff evidence |
| [RUN-20261002-08](RUN-20261002-08/) | Replay with rebuilt event provenance and C$ collection evidence |
| [RUN-20261002-07](RUN-20261002-07/) | Rule-tuning reference; live R22/R23/R24 coverage and measured alert volume |
| [RUN-20261002-06](RUN-20261002-06/) | Bidirectional impact verification; R19 positive; earlier rule suite |
| [RUN-20261002-05](RUN-20261002-05/) | First retained campaign run; one-directional impact comparison; T10 predates R19 coverage |

## Common records

| File family | Contents |
|---|---|
| `RUN-*.json` | Stage status, event/alert references, input/output artifacts, and artifact index |
| `ART-07-01-<token8>.json` | FS01 session-registration receipt |
| `ART-08-01-RUN<nn>.json` | Collection manifest |
| `ART-09-01-round{1,2}-RUN<nn>.json` | Observed sink files and manifest reference for each transfer round |
| `ART-14-01-RUN<nn>.txt` and `.json` | Impact console output and summary |
| `ART-15-01-RUN<nn>.json` | Post-run coverage and verification record |
| `ART-06-02-RUN09.json` | Fixed-target S6 decision, present in RUN-09 |

Filenames and reference completeness vary by run; inspect the ledger's artifact index.
Keep campaign stages **S1–S14** separate from post-run **S15**. Preserve NOT RUN and
PARTIAL statuses rather than converting them to PASS because overall acceptance succeeded.
See the [evidence contract](../README.md) for hash and provenance conventions.

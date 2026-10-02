# evidence/runs — Run records

Each run is a directory containing its ledger and artifacts.

| Path | Contents |
|---|---|
| `RUN-schema.json` | ledger schema (stages / input+output artifacts / artifact_index with sha256) |
| `RUN-20261002-06/` | reference run (current): final campaign re-run - canonical hashes, bidirectional Verify, R19 positive |\n| `RUN-20261002-05/` | first full campaign run S1-S15 |

## RUN-20261002-06 files (current)\n\nMirrors the 05 layout (ledger + ART-07-01/08-01/09-01 x2 with sink_files/14-01/15-01).\n\n## RUN-20261002-05 files (first full run)

| File | Contents |
|---|---|
| `RUN-20261002-05.json` | ledger: 17 stage rows with event references (host/channel/es_id/ts), input/output artifacts, artifact_index with hashes |
| `ART-07-01-18c677ef.json` | S8b/S9 receipt (second session from the WMI pivot) |
| `ART-08-01-RUN05.json` | S10 collection manifest (11 files, per-file hashes) |
| `ART-09-01-round1-RUN05.json` / `round2` | S11a/S11b transfer receipts (11/11 hash match per round against the internal sink) |
| `ART-14-01-RUN05.json` (summary) + `ART-14-01-RUN05.txt` (console output) | S14 impact metrics (Prepare/Run/Verify/Rollback/Verify) |
| `ART-15-01-RUN05.json` | S15 coverage record (stage evidence + alert counts) |

Registration of a new run: create `runs/<run_id>/` with a ledger per `RUN-schema.json`,
index the artifacts it produced, and keep the schema unchanged.


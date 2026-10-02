# evidence/run-ledger — Run records

| File | Contents |
|---|---|
| `RUN-schema.json` | ledger schema (stages / evidence references / artifact index) |
| `RUN-20261002-05.json` | reference run: the final campaign S1-S15 (entry chain → operator → collection → rclone ×2 → RDP → AnyDesk/ProcessHacker → bounded impact) |
| `ART-07-01-18c677ef.json` | S8b/S9 receipt (second session from the WMI pivot) |
| `ART-08-01-RUN05.json` | S10 collection manifest (11 files, per-file hashes) |
| `ART-09-01-round1-RUN05.json` / `round2` | S11a/S11b transfer receipts (11/11 hash match per round against the internal sink) |
| `ART-14-01-RUN05.json` | S14 impact metrics (Prepare/Run/Verify/Rollback/Verify) |
| `ART-15-01-RUN05.json` | S15 coverage record (stage evidence + alert counts) |

Registration of a new run: create `RUN-<id>.json` per `RUN-schema.json`, index the
artifacts it produced, and keep the schema unchanged.
# evidence/run-ledger — run records

| File | Contents |
|---|---|
| `RUN-schema.json` | ledger schema (stages / evidence_refs / artifact index) |
| `RUN-20261002-05.json` | **current** validated run: final campaign S1-S15 (entry chain → operator → collection → rclone ×2 → RDP → AnyDesk/ProcessHacker → bounded impact → E2E verify) |
| `ART-07-01-18c677ef.json` | S8b/S9 receipt (session-2 from the WMI pivot) |
| `ART-08-01-RUN05.json` | S10 collection manifest (11 files, hashes) |
| `ART-09-01-round1-RUN05.json` / `round2` | S11a/S11b transfer receipts (11/11 hash match per round, internal sink) |
| `ART-14-01-RUN05.json` | S14 impact metrics (Prepare/Run/Verify/Rollback/Verify) |
| `ART-15-01-RUN05.json` | S15 scorecard (stage evidence + alert coverage) |

Old-run ledgers/receipts are removed on restructuring — the repo documents the **current**
validated state; history lives in git.
# evidence — Run ledger & artifacts

Evidence policy:

- **One run = one ledger**: `run-ledger/RUN-<id>.json` with stages, evidence references
  and an artifact index; the schema lives in `run-ledger/RUN-schema.json`.
- **Artifacts are handoff proofs**: `ART-XX-01-<token>.json` files carry sha256 payloads
  and producer/consumer stage; server-side receipts (ART-07-01, ART-09-01) confirm
  transfers independently — the receipt hash must equal the manifest hash.
- **Retention**: the repository ships the ledger schema and the reference run
  (RUN-20261002-05) with its artifacts; older run records are superseded in git history.
- Secrets never appear in evidence; per-run credentials stay in gitignored `stage/`.

Reference run: [run-ledger/RUN-20261002-05.json](run-ledger/RUN-20261002-05.json).
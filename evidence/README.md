# evidence — run ledger & artifacts

Evidence policy:

- **One run = one ledger**: `run-ledger/RUN-<id>.json` (stages, evidence_refs, artifact
  index, window). Schema: `run-ledger/RUN-schema.json`.
- **Only the latest validated run is retained** (RUN-20261002-05); older runs are removed
  on restructuring to keep the repo current.
- **Artifacts are handoff-proof**: `ART-XX-01-<token>.json` files carry sha256 payloads
  and producer/consumer stage; receipts (ART-07-01/09-01) are independent server-side
  confirmations; the receipt hash must equal the manifest hash (allowlist).
- No secrets: per-run credentials stay in gitignored `stage/`.

Current run: [run-ledger/RUN-20261002-05.json](run-ledger/RUN-20261002-05.json)
(final campaign S1-S15; artifacts ART-07-01/08-01/09-01×2/14-01/15-01).
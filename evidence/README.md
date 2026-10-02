# evidence — Run ledger & artifacts

Evidence policy:

- **One run = one directory**: `runs/<run_id>/` holds the ledger (`RUN-<id>.json`),
  the artifact files and their raw outputs. The ledger schema lives at
  `runs/RUN-schema.json` and is enforced by `scripts/validate_repo.py`.
- **Artifacts are handoff proofs**: `ART-XX-01-<token>.json` files carry sha256 payloads
  and producer/consumer stage; server-side receipts (ART-07-01, ART-09-01) confirm
  transfers independently — the receipt hash must equal the manifest hash.
- **Event references**: ledger evidence entries carry host, channel, event id,
  Elasticsearch `_id` and UTC timestamp where available, so conclusions can be
  re-verified against the telemetry backend.
- **Retention**: the repository ships the ledger schema and the reference run
  (RUN-20261002-05) with its artifacts; older run records are superseded in git history.
- Secrets never appear in evidence; per-run credentials stay in gitignored `stage/`.

Reference run: [runs/RUN-20261002-05/](runs/RUN-20261002-05/) — summary in
`../reports/reference-run-20261002-05.md`.

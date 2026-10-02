# Evidence model

One run occupies `runs/<run_id>/`: a ledger, indexed artifacts, manifests, receipts,
impact output, and a scorecard. The [ledger schema](runs/RUN-schema.json) defines the
record format. Five runs, **RUN-20261002-05 through -09**, are retained.
The [latest report](../reports/reference-run-20261002-09.md) summarizes RUN-09.

## Evidence types

| Record | What it supports |
|---|---|
| Ledger event reference | Host/channel/event code, Elasticsearch `_id`, UTC time, and join fields where recorded |
| `ART-06-02` (RUN-09) | Executed fixed-scenario target decision for FS01; not a discovery-derived selection algorithm |
| `ART-07-01` | Server-side acceptance of the FS01 second-session registration; not a file-transfer receipt |
| `ART-08-01` | Collection manifest: file names, sizes, and content hashes |
| `ART-09-01` | Transfer receipt: manifest reference and observed sink-file set for one round |
| `ART-14-01` | Bounded-impact output and summary, including recovery verification |
| `ART-15-01` | Post-run verification/coverage record; not another campaign action |

## Hash conventions

Artifact-document hashes use **CRLF → LF normalization before SHA-256**, as implemented
by the acceptance verifier. This applies to indexed artifact documents and the
receipt's `manifest_sha256`. Collection payload content hashes are SHA-256 of the
file bytes; binary files must not be newline-normalized.

For transfer acceptance, compare the entire observed sink set with the manifest:
file name, size, SHA-256, count, and absence of missing or duplicate entries.
The manifest-file hash and an individual transferred file's hash are different values.

## Interpretation

`ACCEPTED` means the verifier's defined assertions succeeded for its supported run.
It does not mean every stage is PASS or every historical technique was reproduced.
RUN-05's committed scorecard uses `PASS`; later scorecards use `ACCEPTED`.
S6 is NOT RUN in 05–08 and executed in 09. S12 remains PARTIAL, with a verified
4624 Type-10 → 4634 Type-10 join; disconnect/reconnect is not separately verified.

Some older ledger notes retain superseded wording about E7 hashes or session lifetime.
The current reports explain those corrections; the underlying evidence files remain
unchanged. Estimated time belongs in `detail`, not in an event `ts` field.
Count parity between local and ingested logs is not per-event reconciliation.

Runtime credentials belong outside committed evidence. Session tokens identify lab
sessions; they are not Windows account credentials. The [fixtures](../scripts/fixtures/)
are synthetic and must never be cited as run evidence.

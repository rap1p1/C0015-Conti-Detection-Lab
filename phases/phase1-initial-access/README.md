# Phase 1 — entry and bootstrap (S1–S3)

A generated laboratory DOCM is opened on WS01 as `duc.user`. Its macro writes the
embedded config, HTA and beacon, then starts mshta. The HTA downloads a benign
DLL-as-JPG and invokes regsvr32; the bootstrap DLL starts the session-1 beacon.
Manual document open substitutes for delivery. This is not evidence of a real
phishing email, password-protected archive or original malware execution.

| Stage | Telemetry and supporting evidence |
|---|---|
| S1 entry/self-write | WINWORD E1/E11 and workflow log; child mshta linked by parent entity |
| S2 HTA/proxy bootstrap | mshta → regsvr32 E1, HTTP-download E3, JPG/marker E11, loader E7 |
| S3 beacon | Proxy → PowerShell E1, entity-owned E3, registration/task/result context |

Children have their own entity IDs. The join is child.parent.entity_id to
parent.process.entity_id, not an identical entity across the chain. The current
entry is direct Office → mshta; a CMD hop in an old fixture is not mandatory.

R01–R09 provide related detection predicates. **R04 does not match WINWORD's
self-writes**; it targets script/proxy writers. E7 hashes are available at
`file.hash.sha256`. Unsigned loading alone does not prove injection or T1553.002.

## Read next

- [Historical entry design and investigation](initial-access-chain-design.md)
- [Current runbook](../../docs/attack-runbook.md)
- [Components](../../payloads/) and [rule catalogue](../../detections/README.md)
- [Latest run evidence](../../evidence/runs/RUN-20261002-09/)

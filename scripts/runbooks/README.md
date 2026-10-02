# scripts/runbooks — operator batches

| File | Stage | Contents |
|---|---|---|
| `c0015-phase2.json` | S4-S5 | the `[OBSERVED-C0015]` discovery set (net/nltest/net view/whoami/tasklist/ping/systeminfo/Get-SmbShare) |

Queue via `POST /runbook?session=<token>&name=c0015-phase2` on the C2-SIM; each entry
is a `{type, cmd}` task executed in order by the beacon (`T-<name>` task ids, results
in `/results`).
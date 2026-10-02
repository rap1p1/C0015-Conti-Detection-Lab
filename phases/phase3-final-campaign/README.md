# Phase 3 — Final Campaign (S10-S15)

Exfiltration, remote access, and bounded impact — mirroring the closing chapters of the
DFIR report — executed end to end in a single run (RUN-20261002-05) and verified across
all stages on Elastic, with detection rules R19-R20 covering the phase.

## Chain (original tools and lab surrogates)

| Stage | Technique (MITRE) | Original tool (report) | Lab surrogate / tool | Evidence (RUN-20261002-05) |
|---|---|---|---|---|
| S10 Collection | T1005/T1039/T1074.001 | ShareFinder re-run; staging; exfiltration from a different server | beacon UNC collection → `\\FS01\C$\C0015\collect\` (11 files) | E11 + S5145 (381; C$:377) + ART-08-01 |
| S11a/b Transfer | T1567.002/T1030 | **rclone → MEGA** (two rounds, `--bwlimit 10M --transfers 7`) | **real rclone** → **local WebDAV sink** on the C2 host (:**9001**) | E1 rclone + E3 :9001 + ART-09-01 receipts (11/11 hash both rounds) |
| S12 RDP | T1021.001 | day-2 RDP to the backup server via the beacon | RDP `mstsc` + `cmdkey`, `it.admin` → FS01 | Security 4624 T3 network; T10 observed (lifetime not captured) |
| S13 Remote tools | T1219.002 | AnyDesk in `Videos\`; ProcessHacker at `C:\` | real AnyDesk (`Videos\`, lab-internal) + ProcessHacker | E11 drop paths + E1 runs |
| S14 Impact | T1486/T1083 | `locker.bat` → Conti (`-m -net -size 10` over `\\HOST\C$`), `readme.txt` note, post-impact listing | `c0015_impact.ps1` bounded surrogate: Prepare→Run(15 files)→Verify(15 mismatches)→Rollback→Verify(hash-equal) | E11 corpus + note; ART-14-01 |

## Engineering posture

- **Sink**: exfiltration terminates at the internal WebDAV sink on the C2 host — no public
  cloud; receipt hash must equal the collection-manifest hash (allowlist).
- **Remote access**: AnyDesk runs lab-internal; ProcessHacker starts without a dump or
  credential read.
- **Impact**: bounded, allowlist-capped, reversible — rollback is verified against the
  backup copy by hash.

## Detection (rules R19-R20)

- **R19** RDP Interactive Logon — Security 4624 `LogonType=10`, non-system account (BB).
  The reference run produced network-auth logons (T3/T4); the rule reports once a fully
  interactive logon is observed.
- **R20** Portable Remote-Access Tool Dropped and Executed — E11 (Videos\ or drive root)
  → E1 (remote-access/process-tool class) sequence; matched 3 alerts in the reference run.
  via E11; matched 3 alerts on the impact notes.

## Files

- [final-campaign-plan.md](final-campaign-plan.md) — the plan with the DFIR cross-check table,
  run procedure, sink design and confinement posture.
- [detection-run-20261002-05.md](detection-run-20261002-05.md) — alert coverage and operational notes.
- Evidence: `../../evidence/runs/RUN-20261002-05/RUN-20261002-05.json` + ART-07-01/08-01/09-01×2/14-01/15-01.
- Verify tool: `../../scripts/verify/verify_final_phases.py` (documented in `../../scripts/README.md`).






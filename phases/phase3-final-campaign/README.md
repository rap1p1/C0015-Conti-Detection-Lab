# Phase 3 — Final Campaign (S10-S15)

Exfiltration, remote access and bounded impact — the "end of the story" per the DFIR
report, executed end-to-end in one run (RUN-20261002-05) and verified across all
stages on Elastic, with new detection rules R19-R21.

## Chain (with original tools from the DFIR report)

| Stage | Technique | Original (report) | Lab surrogate / tool | Evidence (RUN-20261002-05) |
|---|---|---|---|---|
| S10 Collection | T1005/T1039/T1074.001 | ShareFinder re-run; staging; exfil from a different server | beacon UNC collection → `\\FS01\C$\C0015\collect\` (11 files) | E11 + S5145 (381; C$:377) + ART-08-01 |
| S11a/b Transfer | T1567.002/T1030 | **rclone → MEGA** (two rounds, `--bwlimit 10M --transfers 7`) | **real rclone** → local **WebDAV sink** on the C2 host (:**9001**) | E1 rclone + E3 :9001 + ART-09-01 receipts (11/11 hash both rounds) |
| S12 RDP | T1021.001 | day-2 RDP to the backup server via the beacon | RDP `mstsc` + `cmdkey`, `it.admin` → FS01 | Security 4624 T3/T4 (T10 gated) |
| S13 Remote tools | T1219.002 | AnyDesk in `Videos\`; ProcessHacker at `C:\` | real AnyDesk (`Videos\`, lab usage) + ProcessHacker (no dump) | E11 drop paths + E1 runs |
| S14 Impact | T1486/T1083 | `locker.bat` → Conti (`-m -net -size 10` over `\\HOST\C$`), note `readme.txt`, post-impact listing | `c0015_impact.ps1` **bounded** surrogate: Prepare→Run(15 files)→Verify(15 mismatches)→Rollback→Verify(hash-OK) | E11 corpus + note; ART-14-01 |
| S15 E2E/IR | — | — | full-window verify + scorecard | ART-15-01 + ledger |

## Decision record (boundary changes authorized 2026-10-02)

- **AnyDesk**: real tool used; public-relay traffic permitted by the operator (lab-internal
  sessions only). ProcessHacker: no dump / no credential read (E10-study gated).
- **MEGA**: replaced by the internal sink — **no MEGA account/API needed** (rclone local
  remote; receipt hash == manifest hash == allowlist).
- **Impact**: remains bounded and reversible (allowlist corpus, rollback verified).

## Detection (rules R19-R21, validated on-run)

- **R19** RDP Interactive Logon — Security 4624 LogonType=10 non-system (BB; the lab run
  observed T3/T4 network-auth, so the rule is logically validated, gated on a completed logon).
- **R20** Portable Remote-Access Tool Dropped and Executed — E11 (Videos\ / drive root) → E1
  (AnyDesk/RustDesk/TeamViewer/ProcessHacker class) sequence; **fired (3)**.
- **R21** Ransomware Note or Bulk File Extension Change — note class or novel extension via E11;
  **fired (3)** on the impact notes.

## Files

- [final-campaign-plan.md](final-campaign-plan.md) — approved plan: DFIR cross-check table,
  run procedure, safety boundaries, sink design.
- [detection-run-20261002-05.md](detection-run-20261002-05.md) — alert coverage + quality notes
  (R16 suppression debt, R19 gating, legacy-note translation debt).
- Evidence: `../evidence/run-ledger/RUN-20261002-05.json` + ART-07-01/08-01/09-01×2/14-01/15-01.
- Verify tool: `../stage/analysis/verify_final_phases.py` (copy referenced in `../scripts/`).
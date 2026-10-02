# Campaign mapping and fidelity

The campaign execution map is **S1–S14**, with S7b, S8a/S8b and S11a/S11b refinements.
**S15** in retained ledgers is post-run validation. Earlier P0–P15 planning numbers
were a different design scheme; they must not be used interchangeably with ledger stages.

Read this mapping with the [runbook](attack-runbook.md), [architecture](architecture.md),
[correlation model](correlation-architecture.md), [payload implementation](payloads-and-c2.md),
and [latest reference report](../reports/reference-run-20261002-09.md).
The five retained runs establish the recorded lab behaviors, not full historical
equivalence or one uninterrupted beacon session. Run-specific statuses remain authoritative.

## Evidence labels and status vocabulary


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


The ledgers additionally use `PASS`. Overall verifier `ACCEPTED` is distinct from
individual stage status and from detection-rule matches.

## Sources

| Source | Use |
|---|---|
| [MITRE ATT&CK C0015](https://attack.mitre.org/campaigns/C0015/) | Campaign technique/software mapping; retain source uncertainty |
| [The DFIR Report, 2021-11-29](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/) | Original intrusion narrative, observed tools and sequence |
| [Microsoft Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | Event semantics, not evidence of the original intrusion |

Other Bazar/Conti cases and general detection guidance are context, not direct C0015
evidence. Sysmon **15.21/schema 4.91** is the recorded lab version; an unpinned upstream
documentation page is not a reproducible software-version assertion.

## Historical narrative (August 2021)


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


## Current laboratory stage map

| Stage | Laboratory mechanism | Evidence and interpretation |
|---|---|---|
| S1 | Manual open of generated DOCM; macro self-writes config, HTA and beacon | WINWORD-originated E11 and workflow log support self-write; E1 ancestry alone does not prove macro invocation |
| S2 | mshta executes VBScript/JScript HTA; HTTP download of DLL-as-JPG; regsvr32 | E1/E11/E3 and loader E7; VBScript uses MSXML bin.base64, JScript writes a marker |
| S3 | Bootstrap DLL starts PowerShell beacon; C2-SIM registration and task/result loop | Loader → beacon ancestry, beacon-owned E3, server registration context |
| S4 | Discovery through the WS01 beacon and CMD children | E1 command classes; execution does not guarantee useful command output |
| S5 | Share-enumeration commands and output | Lab substitute for PowerView ShareFinder; do not claim AdFind executed from its file drop alone |
| S6 | Fixed scenario target FS01; server-side decision artifact | NOT RUN in 05–08; executed in 09 as ART-06-02, without discovery-derived selection proof |
| S7 | Pre-provisioned it.admin operator context | Authentication events where generated; no proof of original credential provenance |
| S7b | Compiled LSASS-access surrogate | E10 target LSASS, grant 0x1010; placeholder output and decoy dump, no real extraction |
| S8a | WS01 tool fetch and SMB C$ staging to FS01 | E3/E11 plus target 5145 access checks; file hash continuity when recorded |
| S8b | WMI creates rundll32 on FS01; separate pivot DLL invokes LabEntry | E1 parent WmiPrvSE → same-entity unsigned E7, with ECS SHA-256 matching artifact |
| S9 | Pivot DLL starts FS01 beacon; registration accepted | Entity-owned E3 and ART-07-01 receipt; marker alone is insufficient |
| S10 | WS01 operator reads through FS01 C$, stages collection under C$ | 5145/E11 and ART-08-01 manifest; 11 files, 309 bytes |
| S11a/b | WS01 rclone sends two rounds to operator-host WebDAV :9001 | E1/E3 and ART-09-01 full-set equality per round; no MEGA or chunked POST service |
| S12 | Operator-host RDP to FS01 | T10 logon → T10 logoff joined by TargetLogonId; R19 alerts in 06–09 |
| S13 | Portable AnyDesk deployment/execution and ProcessHacker deployment surface | E11/E1 as recorded; public relay observed separately, not used as C2-SIM operator transport |
| S14 | FS01 bounded corpus transformation and note creation | E11 notes, R22/R23 in later runs, impact output; reversible surrogate rather than actual encryption |
| Post-run S15 | Acceptance, scorecard and analyst evaluation | Ground truth and validation; not an additional attacker technique |

## Phase handoffs and fidelity

**Entry → session 1.** Current entry ancestry is Office → mshta → regsvr32 → PowerShell;
the earlier Office → CMD fixture is not a required hop. Macro artifacts and workflow
logs provide corroboration beyond process ancestry. E7 is enabled in the committed
profiles, and hashes are mapped at `file.hash.sha256`. Manual document open replaces
delivery; a retained run is not evidence of a phishing email or password-protected ZIP.

**Discovery → target decision.** RUN-09 records the fixed FS01 decision. The artifact
does not demonstrate an algorithm choosing a host from discovery listings. This is
an orchestration handoff, not a standalone endpoint detection. Earlier NOT RUN rows
remain valid historical statuses.

**Identity → WMI.** A pre-provisioned operator account supplies authorization. S7b
does not generate the credential used by S8: the compiled surrogate emits placeholders.
A successful IPC$ session does not change the caller's process token. 4648 is optional
depending on the authentication path. Join FS01 4624↔4672 on target LogonId; never
join source 4648 to target 4624 by LogonId.

**WMI → session 2.** The retained pivot uses rundll32's documented-in-run space-form
LabEntry invocation. The earlier console-loader workaround was superseded. The
surrogate DLL starts a PowerShell beacon; the DLL itself is not the HTTP task-loop
client. ART-07-01 is written on accepted registration, not after all results complete.
Entity-owned callback telemetry and matching run/host receipt support this handoff.

**Collection → transfer.** The current mechanism reads through C$, so R16 covers the
admin-share access surface. It does not prove a complete content read. ART-08-01
records the collection set; each ART-09-01 records independently observed sink files
and the manifest-document hash. Compare names, sizes and content hashes, not unrelated
hash values. The historical source used MEGA; the lab uses internal WebDAV. T1030 is
mapped to bandwidth-limit configuration for this campaign, not unimplemented chunking.
Run order is empirical: RUN-06's RDP event precedes both transfer rounds, so the
historical between-round ordering must not be asserted for every replay.

**Remote access → impact.** RDP is native, with logon/logoff evidence in all five runs.
4778/4779 reconnect/disconnect is separate and unverified; S12 stays PARTIAL. AnyDesk
is remote-access software; ProcessHacker is a process tool, and its historical LSASS
use is inferred, not a confirmed credential dump. The impact harness runs separately
on FS01, not as a proven descendant of the session-2 beacon. RUN-05 used one-directional
recovery comparison; 06–09 record bidirectional verification.

## Technique distinctions

- Loading a DLL into regsvr32/rundll32 is proxy execution. **E7 does not prove DLL
  injection** into another process. Historical D8B3/143 injection remains analysis-only.
- E10 records access rights. A 0x1010 grant and decoy dump do not establish credential
  extraction or historical Mimikatz use. The original WMI credential provenance stays UNKNOWN.
- Unsigned module status does not by itself reproduce T1553.002 invalid-signature
  behavior. Preserve historical and laboratory technique claims separately.
- Sysmon E19–E21 describe WMI subscription events, not remote process creation.
- E3 is connection telemetry, not HTTP bodies, bandwidth measurement or completed exfiltration.
- E2 is creation-time change, not rename. E11 create/overwrite is not ordinary read
  telemetry and does not guarantee a record for every rename.
- ProcessGuid is same-host only and cannot be decoded into a PID. Old suffix-based
  PID-conflict claims are invalid methodology, not unresolved proof about current runs.

## Evidence and operational scope

The [run directories](../evidence/runs/) preserve per-run provenance and old notes.
Some earlier prose in ledgers still says E7 hash was absent or RDP lifetime uncaptured;
current reports explain the ECS-field correction and appended 4634 joins without
rewriting underlying evidence. A count of 87 local/87 ingested logoffs is count parity,
not per-event reconciliation. Do not invent a cause for absent disconnect events.

Runtime identity is supplied out of band. Simulator command filtering is limited,
not a comprehensive secret scanner or benign-command allowlist. The retained chain
uses benign DLL/beacon/LSASS components, dummy collection, internal transfer and a
bounded reversible impact corpus. It does not execute Bazar, Cobalt Strike, Conti,
process injection or a general-purpose encryptor. Live run evidence and rule matches
remain distinct from historical fidelity, offline tests, and overall acceptance.

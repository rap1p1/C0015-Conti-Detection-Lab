# Campaign behavior and laboratory telemetry

Scope: retained runs **RUN-20261002-05 through -09**, with RUN-09 the latest reference.
This is a comparison of reported historical behaviors and laboratory observables,
not a byte-for-byte comparison against original campaign EVTX or packet captures.
Sources: [MITRE C0015](https://attack.mitre.org/campaigns/C0015/) and
[The DFIR Report](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/).

| Stage | Campaign anchor | Lab signal/evidence | Fidelity boundary |
|---|---|---|---|
| S1 | Word macro entry | WINWORD self-write E11, workflow log, child mshta E1 | Manual DOCM open; no evidence of real phishing delivery |
| S2 | HTA scripting, download and proxy execution | mshta/regsvr32 E1, JPG-as-DLL E11/E7, download E3, marker writes | Benign HTA/DLL; VBScript base64 decode and separate JScript marker |
| S3 | Foothold callback and tasking | PowerShell beacon E1/E3 plus C2 registration/task context | Simulator, not Bazar/Cobalt Strike transport or injection |
| S4–S5 | Discovery and share enumeration | Beacon/CMD/tool E1 and share-enumeration output | Lab commands substitute for some original tooling; execution is not success |
| S6 | Operator target decision | ART-06-02 in RUN-09 selects fixed FS01 | Earlier runs NOT RUN; no discovery-driven selection proof |
| S7/S7b | Identity context; inferred credential-access surface | Security logons and surrogate LSASS E10 0x1010 | Pre-provisioned account; placeholders/decoy dump do not prove extraction |
| S8a | Tool transfer | C$ 5145 access checks, staged E11 and artifact hash | Access checks alone do not prove complete write/read |
| S8b | WMI → rundll32 load | E1 parent WmiPrvSE and same-entity unsigned E7 with `file.hash.sha256` | Separate benign pivot DLL; no injection |
| S9 | Second callback session | Loader → beacon, entity-owned E3, registration receipt | Receipt proves server acceptance, not every subsequent operation |
| S10 | Collection/staging | FS01 C$ checks, staged E11, 11-file manifest | WS01 operator performs collection; consolidated host roles |
| S11a/b | Rclone transfer | rclone E1/E3; two full-set sink receipts | Internal WebDAV substitutes for MEGA; E3 does not measure rate/completion |
| S12 | RDP interactive access | 4624 Type 10 → 4634 Type 10 same-host LogonId join | Reconnect/disconnect not separately verified; ledger status PARTIAL |
| S13 | Portable AnyDesk; ProcessHacker precursor | Drop/execution references as recorded | R20 covers remote-access class, not ProcessHacker or credential extraction |
| S14 | Ransomware impact and listing | Dummy corpus changes, E11 note spread, R22/R23, recovery output | No encryption; RUN-05 earlier one-way Verify, 06–09 bidirectional |

## Corrections to earlier comparisons

- Security telemetry is under **system.security**. The old “not ingested” conclusion
  came from querying the wrong dataset; 5145 also depends on auditing.
- E7 hashes were present at **`file.hash.sha256`**. The older verifier's wrong field
  caused the “unpopulated” interpretation; current acceptance compares the DLL hash.
- The historical console-loader workaround is superseded by the recorded WMI/rundll32
  pivot. Earlier diagnostics do not justify a general session-0 prohibition.
- RDP logon events and R19 alert timestamps are different. RUN-05 has T10 events but
  no in-window R19 coverage; 06–09 have positive R19 references.
- In every retained run, a T10 logoff is joined to a T10 logon. This does not establish
  reconnect/disconnect behavior, and count parity is not per-event reconciliation.
- Historical credential provenance and inferred LSASS behavior remain uncertain. Lab
  E10/placeholder output does not convert them into confirmed theft.

For exact UTC times, Elasticsearch IDs, entities, LogonIds and hashes, use each
[ledger](../evidence/runs/) with its [report](../reports/). The retired September/early
October narrative comparisons are investigation history, not additional reference
datasets. Detection matches, artifact integrity and historical fidelity are separate
conclusions; do not assign blanket “HIGH/1:1” parity to the entire chain.

# Correlation architecture

Three layers must remain distinct: **event joins**, **phase handoffs**, and **run
orchestration**. A nearby timestamp or a successful overall verifier result does
not establish causality. The current rules evaluate raw events; building-block
alerts support analyst investigation rather than an implemented campaign-wide rule.

## 1. Keys and source fields

| Dimension | Key | Scope |
|---|---|---|
| Run | `run_id`, ledger window, host/account, artifacts | Ground truth/enrichment; not a universal Windows event field |
| Process | `process.entity_id` and `process.parent.entity_id` | ProcessGuid ancestry on the same host |
| Authentication | 4624 `TargetLogonId` ↔ 4672 `SubjectLogonId` | Same host and boot/session context |
| RDP lifecycle | 4624 `TargetLogonId` ↔ 4634 `TargetLogonId`, Type 10 | Same host/boot; logoff follows logon |
| Artifact | Path, file size, SHA-256, producer/consumer | Cross-host content continuity plus a documented handoff |
| Network | Entity, destination IP/port, protocol, time | E3 attribution where non-empty; not HTTP contents |

The actual mapped fields must be verified in the dataset. Security ECS logon fields
can differ by event type: use the recorded `winlog.event_data` keys rather than
assuming a populated `winlog.logon.id` on every event. E7 hashes in the retained
events are at **`file.hash.sha256`**, not the older verifier's assumed field.
Run IDs can appear in command/config context; that is enrichment, not a standard
event-to-run key. Multiple beacon registrations in RUN-09 require separate entity
and token segments, not one assumed uninterrupted process.

## 2. Evidence tiers

| Tier | Meaning |
|---|---|
| `DIRECT EVENT LINK` | A valid same-host entity/logon key or independently matched content hash links specific records |
| `SUPPORTED PHASE HANDOFF` | Producer/consumer evidence and matching artifact/run context support a handoff |
| `TEMPORAL/CONTEXTUAL ONLY` | Time, account or host context agrees, but a causal key is absent |
| `UNPROVEN` | Required evidence is absent or inconclusive |
| `CONTRADICTED` | Evidence conflicts with the proposed linkage |

Empty/all-zero entity IDs, mismatched logon IDs, uncertain PID lifetimes, clock skew,
reused marker names, or missing network attribution require a downgrade. A PID can
support investigation only with host, process lifetime and time context; it does not
repair a missing ProcessGuid into a direct entity join. Never decode a ProcessGuid
suffix as a PID. Measure clock skew for the actual participating hosts.

## 3. Implemented behaviors and investigation links

| Chain segment | Evidence link | Current rule/evidence scope |
|---|---|---|
| Entry/bootstrap | Office entity → child mshta → proxy loader; E7 in loader; loader → PowerShell | R01–R09; retained direct Office → mshta path does not require a CMD hop |
| Discovery | Beacon → CMD ancestry → discovery tool | R10–R13; command execution does not prove every discovery command succeeded |
| Target decision | Run-specific `ART-06-02`, selected FS01 | RUN-09 fixed scenario decision; no discovery-output-to-selection proof |
| Authentication | FS01 4624↔4672 LogonId, where corresponding records exist | R14a/R14b are separate building blocks; cross-host source attribution needs account/IP/time/auth context |
| LSASS surface | Tool process and E10 source entity, LSASS target, grant 0x1010 | R15; access rights do not establish memory extraction; decoy dump is not a real LSASS dump |
| Handoff/WMI | 5145 access checks + staged file; WmiPrvSE child → same-entity E7 unsigned load | R16/R17; DLL hash verifies loaded content |
| Session 2 | Loader → beacon entity; E3 owned by beacon; matching registration receipt | R18/R09 plus ART-07-01; receipt proves registration, not all subsequent commands |
| Collection/transfer | Staging manifest → two observed sink sets, per-file equality | R16/R24; file-read completion is not proven by E11 or 5145 alone |
| RDP | 4624 T10 → 4634 T10, same FS01 TargetLogonId | R19 + ledger lifecycle references; reconnect/disconnect not separately verified |
| Portable remote tool | E11 drop followed by E1 execution on same host | R20 host-only correlation; path/hash cross-check remains analyst work |
| Impact | E11 note paths grouped by host/process entity; impact output and rollback record | R22/R23; file fan-out/notes do not prove encryption |

RUN-05 through -09 contain the RDP logon-to-logoff joins. S12 retains PARTIAL status
because 4778/4779 are separately unverified. RUN-05 lacks in-window R19 alerts because
rule coverage began later, not because its T10 logons were absent.

Historical C1 discovery-to-collection aggregation was retired. Its synthetic fixture
remains for component/design tests; it is not an active rule or a current campaign
correlation. Historical injection branches are analysis-only and must not be inferred
from the unsigned DLL loads or the LSASS-access surrogate.

## 4. Mandatory event semantics

- ProcessGuid joins are **same-host only**. Child and parent have different entity
  IDs; connect the child's parent entity to the parent's process entity.
- 4624↔4672 uses **TargetLogonId ↔ SubjectLogonId** on the target host.
  4624↔4634 uses **TargetLogonId ↔ TargetLogonId**, with account/type/time/boot context.
- **Never join WS01 4648 to FS01 4624 by LogonId.** Correlate account, source/destination,
  time and authentication context; LogonGuid is usable only when present, non-zero
  and independently verified. 4648 is not generated by every WMI authentication path.
- Sysmon **E19–E21** describe WMI filter/consumer/binding activity, not remote WMI
  process creation. T1047 evidence includes target E1 **WmiPrvSE → child**.
- **E3** describes TCP/UDP connections, not ICMP, URL paths, bodies, transfer byte
  counts, JA3/JA4, TLS certificates, chunking, bandwidth rate or transfer completion.
- **E7** describes a module load in its recorded process. Unsigned status alone does
  not prove malicious code, injection, or invalid-signature behavior (T1553.002).
- **E10** records process access and rights. It does not prove those rights were used
  to extract credentials or inject into the target.
- **E11** describes file create/overwrite, not ordinary reads or a guaranteed record
  of every rename. **E2** is creation-time change, not rename.
- **5145** is a share access check. Object-access auditing/SACLs can provide 4663;
  manifests and receipts are still needed for content/transfer conclusions.
- **4672** describes privileges assigned to a logon; it does not prove local-group
  membership. **4779** is disconnect, **4778** reconnect, **4634** logoff, and **4647**
  user-initiated logoff.

## 5. Verification boundary

The [acceptance verifier](../scripts/verify/verify_final_phases.py) checks selected
events, ancestry, DLL hash, session receipt, transfer-set equality, tool ordering,
impact output and artifact integrity for supported runs. It uses run-specific windows
and expected lab values. Those are verification anchors, not detection-rule predicates.
Its 4634 lookup is informational; a successful acceptance result alone is not proof
that every temporal/boot condition has been enforced by code. Assess the referenced
records as well. Archived alert references can be accepted after alert-index cleanup.

For independent review, record host/channel/RecordID, Elasticsearch `_id`, UTC event
time, entity/logon keys, and artifact hashes. Compare LOCAL OBSERVED with INGEST
VERIFIED when local exports exist. RUN-09's 87 local and 87 ingested 4634 records show
**count parity**, not a per-event reconciliation. Missing 4778/4779 does not by itself
identify a cause. No separate RDP replay is required to support the already recorded
logon-to-logoff conclusion.

Live replay evidence demonstrates positive matches in this lab. Broad false-positive
performance, negative controls and variations require separate measurements; 20
offline component tests do not execute EQL or establish detection sensitivity.

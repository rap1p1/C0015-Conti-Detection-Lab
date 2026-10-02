# Payload and C2 implementation

This document describes the components represented by the retained reference runs,
not every option proposed during design. The active initial and operator channel is
**C2-SIM on the Windows host**. CALDERA, Sliver and Havoc were considered earlier;
none is part of the documented deployed chain.

## Components and process ownership

| Stage | Component | Implemented behavior |
|---|---|---|
| S1 | Generated Word macro | Writes embedded config/HTA/beacon and starts mshta; manual document open replaces delivery |
| S2 | `bootstrap.hta` | VBScript decodes benign base64, downloads DLL-as-JPG and launches regsvr32; JScript writes its marker |
| S2–S3 | `c0015_bootstrap_dll.c` | DllRegisterServer bootstrap writes a marker and starts the session-1 PowerShell beacon |
| S3/S9 | `c0015_beacon.ps1` | Registration, default task stream, queued operator commands, result posting |
| S6 | Simulator target-decision task | Writes fixed-target FS01 decision artifact in RUN-09 |
| S7b | `c0015_mimikatz_surrogate.c` | Opens LSASS with 0x1010 rights, emits benign placeholder output and a decoy dump file |
| S8b–S9 | `c0015_143_surrogate.c` | LabEntry in rundll32 writes a marker and starts the FS01 beacon |
| S10–S11 | WS01 operator processes + rclone | Collection through FS01 C$, then two transfers to internal WebDAV |
| S13 | AnyDesk / ProcessHacker | Remote-tool/process-tool deployment surfaces; not replacement C2-SIM channels |
| S14 | `c0015_impact.ps1` | Bounded file-name transformation, notes, verification and rollback on FS01 |

The bootstrap and pivot DLLs are **separate source files**, not one interchangeable
artifact. All runtime child processes have their own entity IDs; DLL load evidence
belongs to the loader process. FS01's session-2 beacon does not parent every subsequent
collection, RDP or impact action. Refer to the [runbook](attack-runbook.md) for host roles.

## Simulator interface

| Endpoint | Method | Purpose |
|---|---|---|
| `/session/register` | POST | Accept stage/host/token/run context; same-token re-registration preserves existing in-memory state |
| `/task/next` | GET | Return queued OP-CMD first, then default task stream and sleep |
| `/result` | POST | Accept bounded result and retain recent output in memory |
| `/cmd` | POST | Queue an operator-supplied command for a registered session |
| `/runbook` | POST | Queue ordered `cmd`/`pause` entries from the named batch |
| `/sessions` | GET | Inspect current in-memory session registrations |
| `/results` / `/last` | GET | Read recent command output (ring of at most 32 results) |
| `/checkin` | GET | Legacy callback path; separate from normal register/task/result flow |

Tokens are lab session identifiers, not account credentials. The beacon reads its
token from the configured environment/file mechanism or generates one, and adopts
the server's canonical token after registration. A `phase7-session2` registration
writes **ART-07-01**; that receipt is not dependent on completion of every later task.

The current beacon runs until stopped, except `-Once`; **`loop_count` is advisory**.
Older run notes attributing relaunches to a loop-count limit describe earlier guest
state and must not be generalized to current source. In-memory queues/results are
lost on server restart. The watchdog restores the process, not persisted session state.

## Control model and evidence boundary

Default task identifiers and stage/host checks constrain parts of the protocol,
but raw `/cmd` and runbook commands are dynamic. The credential-string filter checks
a small set of patterns; it is neither a benign-command allowlist nor a comprehensive
secret scanner. Benign behavior depends on the supplied surrogates and operator scope.
Result bodies stay in an in-memory ring; simulator logs describe metadata/lengths
rather than those bodies. Operator command strings can be logged.

The LSASS surrogate does not read LSASS memory or extract credentials. The **0x1010**
handle includes VM_READ permission; the event records access rights, not actual
extraction. Its NTLM-shaped strings and `lsass.dmp` are benign placeholders/decoy data.
S7's pre-provisioned account remains distinct from this signal-generation step.
Historical injection is analysis-only. Unsigned loading alone does not reproduce
invalid code-signature handling or process injection.

## Transfer and impact

The implemented transfer is **real rclone → internal WebDAV :9001**, replacing MEGA.
Receipts describe 11 observed files per round (309 bytes of collection content), with
name/size/hash equality against ART-08-01. The old `p5_sink.py`, :8081 and chunked
POST proposal was superseded and is not a committed service. The C0015 mapping ties
T1030 to rclone bandwidth limiting; command-line `--bwlimit` records configuration,
while E3 alone cannot measure the transfer rate. Check each run's timestamps instead
of assuming RDP always fell between its two transfer rounds.

The impact component transforms an allowlisted dummy corpus and creates notes; it
does not encrypt real user data. RUN-05 used an earlier one-directional comparison;
06–09 record bidirectional Verify and rollback hash equality. Those results concern
file content/name state, not a complete enterprise recovery or separately measured
ACL restoration.

Historical campaign fidelity is intentionally partial: manual delivery, benign DLLs,
pre-provisioned identity, no injection, internal sink and bounded impact replace
original malware/infrastructure. Preserve UNKNOWN/INFERRED source labels rather
than filling historical gaps with laboratory implementation choices.

# Detection measurement — RUN-20261002-05

Window: **2026-10-02 05:41:00Z–06:12:00Z**. This is a historical measurement of
the suite at that run, not the current 24-rule deployment.

## Campaign and evidence

The replay includes entry, WS01 operator actions, SMB/WMI pivot, second-session
registration, 11-file collection, two rclone rounds, RDP, portable-tool deployment
and bounded impact/recovery. **S6 was NOT RUN**. S15 is post-run evaluation rather
than another attacker stage. RUN-05's impact comparison was one-directional;
later runs provide bidirectional Verify evidence.

Artifacts include ART-07-01-18c677ef, ART-08-01, ART-09-01 rounds 1/2, ART-14-01,
and ART-15-01. See the [ledger](../../evidence/runs/RUN-20261002-05/RUN-20261002-05.json)
and [corrected report](../../reports/reference-run-20261002-05.md).

## Historical stored alert counts

| Rule | Documents |
|---|---|
| R16 | 340 |
| R14b | 288 |
| R10 | 78 |
| R14a | 72 |
| R12 | 33 |
| R11 | 9 |
| R18 | 9 |
| R13 | 8 |
| R17 | 3 |
| R15 | 2 |
| R20 | 3 |
| R21 (later retired) | 3 |
| R19 | 0 |

Counts came from the historical alert sweep and include overlapping-window matches;
they are not unique activities, incidents or false positives. R16 represents
admin-share **access checks**, not confirmed writes. Its later suppression groups
on host + SubjectLogonId + ShareName; an earlier proposed RelativeTargetName grouping
was not the final exported configuration.

## Corrected interpretations

- RUN-05 has **two Type-10 logons at 06:00:27.723Z**. R19 had no in-window rule
  coverage; the earlier “no interactive logon” explanation was wrong.
- The first logon, FS01 TargetLogonId **0x2d1c6d0**, has a joined Type-10 **4634 at
  06:01:07.328Z**. The second T10's lifecycle is not established by that join.
- Type 4 is batch, not RDP-specific network authentication. Disconnect/reconnect
  events remain separate from logoff.
- R20's current query covers AnyDesk/RustDesk/TeamViewer. ProcessHacker deployment
  is separate evidence, and R20's host-only sequence does not identify the dropped
  file as the exact executed binary.
- R21 was retired; R22/R23/R24 were introduced before RUN-07. Do not rewrite this
  run's counts as though those later rules were present.
- The second-session beacon relaunch recorded in the ledger must be kept as a
  distinct process segment. Matching run_id alone does not establish continuous ancestry.

Current metadata, suppression and analyst guidance are in the
[rule catalogue](../../detections/README.md). The generator's source loading and
export validation are distinct from EQL execution and detection-performance tests.

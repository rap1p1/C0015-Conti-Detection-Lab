# Experiments

## EQL parent-child correlation

Early validation used entity-aware EQL to verify parent-child process relationships instead of relying only on PID values.

Example concept:

```eql
sequence by host.id with maxspan=2m
  [process where event.type == "start" and process.name == "cmd.exe"] by process.entity_id
  [process where event.type == "start" and process.parent.name == "cmd.exe"] by process.parent.entity_id
```

The experiment demonstrated why `process.entity_id` and `process.parent.entity_id` are stronger correlation keys than reusable numeric PIDs.

## Temporal constraint experiment

A `cmd.exe -> tasklist.exe` sequence initially failed because the shell had been opened longer than the EQL `maxspan`. Reopening a fresh shell and executing `tasklist` immediately produced a match.

Lesson: `maxspan` is a real temporal constraint, not just a query decoration.
## VMware false-positive analysis

Benign VMware Tools activity produced `vmtoolsd.exe -> cmd.exe` process chains during VM power-on/resume. This showed why detecting `cmd.exe` alone is not meaningful.

A narrow Sysmon exclusion was added only for the VMware Tools lifecycle script pattern, preserving other command-shell telemetry.

## Building-block duplication experiment

The account/group discovery action generated multiple `net.exe`/`net1.exe` signals, and one SMB file read generated multiple 5145 alerts.

The final correlation was therefore designed around `COUNT_DISTINCT` behavior families rather than total alert count.

## Final correlation validation

The complete chain was replayed within a short window. Five atomic detections fired and the ES|QL correlation generated one Medium Elastic Security alert with risk score 60.

For faster validation, rule intervals were temporarily reduced to one minute and returned to a production-like cadence afterward.

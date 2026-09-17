# Detections

Detection rules for the C0015 Conti Detection Lab, organized by type.

## Directory Structure

- `atomic/` — Low-confidence KQL building blocks. Each rule targets a single ATT&CK behavior family and is intentionally broad to preserve recall.
- `eql/` — Entity-aware EQL prototypes used for telemetry validation of parent-child process relationships. Development/validation tools, not production detections.
- `correlations/` — Analyst-facing ES|QL correlation logic. These rules combine multiple atomic signals across hosts to produce actionable alerts.

## Design Philosophy

Atomic rules preserve recall by detecting broadly within bounded behavior families. They have no notification actions and exist solely as reusable signals.

The correlation layer reduces noise by counting distinct behavior families, requiring collection activity, enforcing cross-host context, and applying temporal constraints.

## Validated Detections

| Layer | Rule | Status |
|---|---|---|
| Atomic | Windows Process Discovery via Tasklist | DETECTED |
| Atomic | Domain Groups Discovery via Net | DETECTED |
| Atomic | Domain Trust Discovery via NLTest | DETECTED |
| Atomic | Network Share Discovery via Net View | DETECTED |
| Atomic | Remote SMB File Read from Network Share | DETECTED |
| Correlation | Suspicious Discovery and Network Share Collection Chain | DETECTED |

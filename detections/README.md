# Detections

- `atomic/` contains low-confidence KQL building blocks.
- `eql/` contains entity-aware EQL prototypes used for telemetry validation.
- `correlations/` contains analyst-facing ES|QL correlation logic.

The atomic rules are intentionally broad enough to preserve recall. The final correlation reduces noise by counting distinct behavior families and requiring collection plus cross-host context.

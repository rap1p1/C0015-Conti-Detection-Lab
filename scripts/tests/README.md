# Offline component tests

[test_offline.py](test_offline.py) contains **20 tests** covering artifact integrity,
secret-key rejection in artifact data, manifests/receipts, score behavior, simulator
registration/tasking/results/session receipts, and synthetic-fixture checks.

```bash
python -m unittest discover -s scripts/tests
```

Run this command from the repository root. The suite does **not** parse or execute EQL,
validate detection performance, contact Elastic, or run a VM campaign. Fixture
checks validate the supplied synthetic data and historical C1 conditions; passing
them is not evidence that the current rules matched real telemetry.
Live/run-specific acceptance is documented in [scripts/README.md](../README.md).

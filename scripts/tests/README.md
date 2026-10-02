# scripts/tests — offline tests

`test_offline.py` validates rule queries against `../fixtures/` without Elastic
(loads each fixture, applies the rule's EQL logic, asserts expected match/miss).

```
python -m unittest discover -s scripts/tests
```

Fixtures cover the full signal set: E1 entry chain, E3 network, E7 ImageLoad,
E10 LSASS probe, E11 staging/dll writes, S4624/S4625 logons, S5145 share access.


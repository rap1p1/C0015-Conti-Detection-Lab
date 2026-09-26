# Telemetry fixtures — SYNTHETIC REPLAY ONLY

Every `*.json` file in this directory is a **synthetic fixture**: a hand-crafted,
ECS-shaped event document used for offline correlation tests and replay design.

- These are **NOT real lab telemetry**. They must never be cited as evidence of
  any lab run. Every fixture carries `"synthetic": true` and `"note"` saying so.
- Use: offline unit tests (`scripts/tests/test_offline.py`), rule design for
  correlation tiers (see `docs/correlation-architecture.md`), and Elastic replay
  experiments (ingest into an isolated index only, never the production namespace).

Fixtures:
| File | Fixture kind | Purpose |
|---|---|---|
| `e1_winword_cmd.json` | E1 ProcessCreate WINWORD→cmd | S1 chain (parent-child) |
| `e1_mshta.json` | E1 ProcessCreate mshta | S2 chain |
| `e1_regsvr32.json` | E1 ProcessCreate regsvr32 | S2 chain |
| `e7_imageload.json` | E7 ImageLoad unsigned DLL | S2/S9 load evidence (hash) |
| `e11_dll_write.json` | E11 FileCreate DLL | S2/S8 tool handoff |
| `e3_network_unknown_process.json` | E3 NetworkConnect with **null ProcessGuid** | E3 attribution gap (P1-B lesson) — downgrade trigger |
| `s4648_explicit_credential.json` | S4648 explicit credential use | S7/S8 auth evidence |
| `s4624_wmi_logon.json` | S4624 Type 3 + LogonId | S8 auth evidence |
| `s4625_denied.json` | S4625 denied logon | S7 control (duc.user denied) |
| `s5145_collection.json` | S5145 share read | S10 collection evidence |
| `e10_lsass_probe.json` | E10 ProcessAccess → lsass.exe | S13b C-LSASS branch (detection design only) |
| `c1_alerts_fixture.json` | 6 synthetic alert docs | C1 correlation conditions (≥4 families, ≥1 collection, ≥2 hosts) |

Check with: `python scripts/lab_tools.py fixture-check scripts/fixtures`

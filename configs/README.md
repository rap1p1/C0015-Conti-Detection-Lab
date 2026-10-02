# configs — Agent configuration

| File | Purpose |
|---|---|
| `sysmon/sysmon-c0015-balanced.xml` | balanced Sysmon config used during runs (E1/E3/E7/E10/E11 etc.; digest logging, image-load for unsigned-match rules) |
| `sysmon/sysmon-c0015-capture.xml` | capture-oriented config (higher fidelity; use for dedicated verification sessions) |

Install (on each monitored VM, admin):

```
sysmon64 -c configs/sysmon/sysmon-c0015-balanced.xml
```

Security-side prerequisites are documented in `../docs/architecture.md` and in the
runbooks (audit subcategories: `Detailed File Share`, `Logon`, `Other Logon/Logoff Events`).
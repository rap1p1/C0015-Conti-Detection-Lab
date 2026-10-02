# Synthetic telemetry fixtures

These **11 JSON fixtures** are hand-authored test/design data. Every file is marked
`synthetic: true`; none is real lab telemetry or evidence that a campaign step ran.

| Fixture | Purpose |
|---|---|
| [c1_alerts_fixture.json](c1_alerts_fixture.json) | Historical C1 aggregation example; C1 is retired |
| [e10_lsass_probe.json](e10_lsass_probe.json) | Synthetic LSASS-access signal; distinct from real run references |
| [e11_dll_write.json](e11_dll_write.json) | Staging write example |
| [e1_mshta.json](e1_mshta.json) | Script-host process example |
| [e1_regsvr32.json](e1_regsvr32.json) | Proxy-loader process example |
| [e1_winword_cmd.json](e1_winword_cmd.json) | Historical Office → CMD process example |
| [e3_network_unknown_process.json](e3_network_unknown_process.json) | Missing process attribution; correlation downgrade case |
| [e7_imageload.json](e7_imageload.json) | Unsigned module-load example |
| [s4624_wmi_logon.json](s4624_wmi_logon.json) | Network logon with LogonId |
| [s4625_denied.json](s4625_denied.json) | Denied-logon example |
| [s5145_collection.json](s5145_collection.json) | Share-access-check example; not proof of full file read |

The [offline tests](../tests/) check fixture properties and component behavior.
They do not replay the current EQL queries. This directory has no 4648 fixture.
The Office → CMD example also differs from the direct Office → mshta entry observed
in current runs. Use [run ledgers](../../evidence/runs/) for real evidence.

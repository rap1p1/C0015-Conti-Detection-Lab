# Phase 2 — operator and pivot (S4–S9)

The Windows host tasks the WS01 beacon through C2-SIM. Discovery/share enumeration,
pre-provisioned operator context, tool handoff and WMI execution lead to an FS01
second session. The retained runs use benign DLL/LSASS components.

| Stage | Implemented behavior | Evidence/rules |
|---|---|---|
| S4 | Discovery through beacon/CMD ancestry | E1; R10–R12 |
| S5 | Share-enumeration command classes | E1/output; R13; AdFind file drop alone is not execution |
| S6 | Fixed FS01 scenario decision in RUN-09 | ART-06-02; NOT RUN in 05–08 |
| S7 | Pre-provisioned it.admin context | Security logons/privileges where generated; R14a/R14b |
| S7b | Surrogate LSASS access, placeholders and decoy dump | E10 grant 0x1010; R15; no credential extraction |
| S8a | Tool fetch and C$ staging to FS01 | E3/E11, 5145 access checks; R16 |
| S8b | WmiPrvSE → rundll32 → pivot DLL | E1/E7 entity and hash continuity; R17 |
| S9 | Pivot DLL → FS01 beacon → accepted registration | Entity-owned E3 and ART-07-01; R18 |

The original campaign's WMI credential provenance remains UNKNOWN; the laboratory
surrogate does not resolve it. ProcessHacker LSASS use in the historical narrative
is inferred, not a confirmed dump or historical Mimikatz execution.

Security uses **system.security**. Join FS01 4624.TargetLogonId to
4672.SubjectLogonId on the same host/boot context. Never join WS01 4648 to FS01 4624
by LogonId. E19–E21 concern WMI subscriptions, not remote process creation.
The pivot DLL's E7 hash is at `file.hash.sha256`; registration receipt and callback
telemetry support session 2 independently of marker existence.

- [Historical gap investigation](operator-phase-context-gaps-runbook.md)
- [Current runbook](../../docs/attack-runbook.md) and [correlation keys](../../docs/correlation-architecture.md)
- [Rule catalogue](../../detections/README.md) and [command batch data](../../scripts/runbooks/c0015-phase2.json)
- [Latest evidence](../../evidence/runs/RUN-20261002-09/)

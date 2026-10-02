# Query sources

There are **24 source files**. R01–R20 (including R14a/R14b) and R22/R24 are EQL.
**R23 is KQL for a threshold rule**, despite its `.eql` filename; its grouping and
cardinality are exported by the generator. R21 is retired.

| Source | Rule | Stage |
|---|---|---|
| [r01-office-spawns-script-host-shell.eql](r01-office-spawns-script-host-shell.eql) | R01 | S1 |
| [r02-script-host-spawning-proxy-loader.eql](r02-script-host-spawning-proxy-loader.eql) | R02 | S2 |
| [r03-proxy-loader-loading-unsigned-module.eql](r03-proxy-loader-loading-unsigned-module.eql) | R03 | S2/S8b |
| [r04-script-or-proxy-staging-file-write.eql](r04-script-or-proxy-staging-file-write.eql) | R04 | S2 |
| [r05-proxy-loader-spawning-powershell.eql](r05-proxy-loader-spawning-powershell.eql) | R05 | S3/S9 |
| [r06-script-host-network-egress.eql](r06-script-host-network-egress.eql) | R06 | S2–S3/S9 |
| [r07-office-to-mshta-to-proxy-loader.eql](r07-office-to-mshta-to-proxy-loader.eql) | R07 | S1–S2 |
| [r08-unsigned-module-load-to-powershell.eql](r08-unsigned-module-load-to-powershell.eql) | R08 | S2–S3/S8b–S9 |
| [r09-proxy-spawned-powershell-network-egress.eql](r09-proxy-spawned-powershell-network-egress.eql) | R09 | S3/S9 |
| [r10-powershell-spawning-nested-cmd.eql](r10-powershell-spawning-nested-cmd.eql) | R10 | S4 |
| [r11-nested-cmd-launching-discovery-tool.eql](r11-nested-cmd-launching-discovery-tool.eql) | R11 | S4 |
| [r12-powershell-nested-cmd-launching-discovery.eql](r12-powershell-nested-cmd-launching-discovery.eql) | R12 | S4 |
| [r13-share-enumeration-commands.eql](r13-share-enumeration-commands.eql) | R13 | S5 |
| [r14a-network-logon-by-user.eql](r14a-network-logon-by-user.eql) | R14a | S7 |
| [r14b-elevated-privileges-assigned-to-user.eql](r14b-elevated-privileges-assigned-to-user.eql) | R14b | S7 |
| [r15-lsass-credential-access.eql](r15-lsass-credential-access.eql) | R15 | S7b |
| [r16-admin-share-remote-file-write.eql](r16-admin-share-remote-file-write.eql) | R16 | S8a/S10 |
| [r17-wmiprvse-spawns-process-loading-unsigned-module.eql](r17-wmiprvse-spawns-process-loading-unsigned-module.eql) | R17 | S8b |
| [r18-proxy-spawned-powershell-egress.eql](r18-proxy-spawned-powershell-egress.eql) | R18 | S3/S9 |
| [r19-rdp-interactive-logon.eql](r19-rdp-interactive-logon.eql) | R19 | S12 |
| [r20-portable-remote-access-tool.eql](r20-portable-remote-access-tool.eql) | R20 | S13 |
| [r22-ransomware-note-class.eql](r22-ransomware-note-class.eql) | R22 | S14 |
| [r23-note-spread-distinct-paths.eql](r23-note-spread-distinct-paths.eql) | R23 | S14 |
| [r24-transfer-tool-egress.eql](r24-transfer-tool-egress.eql) | R24 | S11 |

The [generator](../../scripts/rules/gen_rules_ndjson.ps1) loads the sources and adds
metadata, schedule, building-block and suppression settings. It produces the
[11-rule](../exports/c0015-rules-r01-r11.ndjson) and
[13-rule](../exports/c0015-rules-r12-r24.ndjson) import bundles.
The [catalogue](../README.md) gives the exact exported names and behavioral scope.
Name-derived rule IDs change when a rule is renamed; do not assume rename-stable IDs.

# eql — Rule files R01-R20

One `.eql` file per rule; regenerated into import NDJSON by
`../stage/analysis/gen_rules_ndjson.ps1` (which must list every rule id in its `$q`
loader). The full index, severity, suppression and stage mapping live in
`../README.md`; this folder only stores the query sources.

| File | Rule | Stage |
|---|---|---|
| `r01-office-spawns-script-host-shell.eql` | R01 | S1 |
| `r02-script-host-spawning-proxy-loader.eql` | R02 | S1 |
| `r03-proxy-loader-loading-unsigned-module.eql` | R03 | S1 |
| `r04-script-or-proxy-staging-file-write.eql` | R04 | S1/S2 |
| `r05-proxy-loader-spawning-powershell.eql` | R05 | S2 |
| `r06-script-host-network-egress.eql` | R06 | S2 |
| `r07-office-to-mshta-to-proxy-loader.eql` | R07 | S1 |
| `r08-unsigned-module-load-to-powershell.eql` | R08 | S1/S2 |
| `r09-proxy-spawned-powershell-network-egress.eql` | R09 | S2-S3 |
| `r10-powershell-spawning-nested-cmd.eql` | R10 | S4 |
| `r11-nested-cmd-launching-discovery-tool.eql` | R11 | S4 |
| `r12-powershell-nested-cmd-launching-discovery.eql` | R12 | S4 |
| `r13-share-enumeration-commands.eql` | R13 | S5 |
| `r14a-network-logon-by-user.eql` | R14a | S7 |
| `r14b-elevated-privileges-assigned-to-user.eql` | R14b | S7 |
| `r15-lsass-credential-access.eql` | R15 | S7b |
| `r16-admin-share-remote-file-write.eql` | R16 | S8a/S10 |
| `r17-wmiprvse-spawns-process-loading-unsigned-module.eql` | R17 (🔴) | S8b |
| `r18-proxy-spawned-powershell-egress.eql` | R18 (🔴) | S9/S2 |
| `r19-rdp-interactive-logon.eql` | R19 | S12 |
| `r20-portable-remote-access-tool.eql` | R20 | S13 |

Import artifacts: `C0015-S1-S3-elastic-rules.ndjson` (R01-R11) and
`C0015-S4-S9-elastic-rules.ndjson` (R12-R20) — regenerated on every run of the generator.


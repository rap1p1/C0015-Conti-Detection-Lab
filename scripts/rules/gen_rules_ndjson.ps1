# gen_rules_ndjson.ps1 - build detections/exports bundles (R01-R11, R12-R20)
# Sources: detections/queries/*.eql  |  Exports: detections/exports/*.ndjson
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$commit = (git -C $repo rev-parse HEAD).Trim()
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

function T { param([string]$Tid, [string]$Tname, [string]$Tref, [string]$Sid, [string]$Sname, [string]$Sref)
  @{ framework = 'MITRE ATT&CK'; tactic = @{ id = $Tid; name = $Tname; reference = $Tref }
     technique = @(@{ id = $Sid; name = $Sname; reference = $Sref }) }
}
$tDiscov  = @{ id='TA0007'; name='Discovery'; reference='https://attack.mitre.org/tactics/TA0007/' }
$tLatMv   = @{ id='TA0008'; name='Lateral Movement'; reference='https://attack.mitre.org/tactics/TA0008/' }
$tExec    = @{ id='TA0002'; name='Execution'; reference='https://attack.mitre.org/tactics/TA0002/' }
$tCred    = @{ id='TA0006'; name='Credential Access'; reference='https://attack.mitre.org/tactics/TA0006/' }
$tC2      = @{ id='TA0011'; name='Command and Control'; reference='https://attack.mitre.org/tactics/TA0011/' }
$tDefEv   = @{ id='TA0005'; name='Defense Evasion'; reference='https://attack.mitre.org/tactics/TA0005/' }
function Tech { param($Tactic, [string]$Id, [string]$Name, [string]$SubId=$null, [string]$SubName=$null)
  if ($SubId) {
    @{ framework='MITRE ATT&CK'; tactic=$Tactic; technique=@(@{ id=$Id; name=$Name; reference="https://attack.mitre.org/techniques/$Id/"; subtechnique=@(@{ id=$SubId; name=$SubName; reference="https://attack.mitre.org/techniques/$SubId/" }) }) }
  } else {
    @{ framework='MITRE ATT&CK'; tactic=$Tactic; technique=@(@{ id=$Id; name=$Name; reference="https://attack.mitre.org/techniques/$Id/" }) }
  }
}

function New-Rule {
  param([string]$Id, [string]$RuleId, [string]$Name, [string]$Descr, [string]$Note, [string]$Sev,
        [int]$Risk, [string[]]$FP, [object]$Threat, [string[]]$Idx, [string]$Query, [string]$BBlock)
  # Deterministic uuid4 (forced version/variant nibbles) derived from the rule name so
  # re-imports overwrite the same rule instead of duplicating it. Renaming a rule
  # changes its id - migrate server-side (delete old, import new) on renames.
  $hash = ([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Name)) |
           ForEach-Object { $_.ToString('x2') }) -join ''
  $uuid = '{0}-{1}-4{2}-8{3}-{4}' -f $hash.Substring(0,8), $hash.Substring(8,4),
          $hash.Substring(12,3), $hash.Substring(15,3), $hash.Substring(18,12)
  $o = [ordered]@{
    id = $uuid; rule_id = $uuid; name = $Name; immutable = $false; version = 1; revision = 0
    updated_at = $now; updated_by = 'elastic'; created_at = $now; created_by = 'elastic'
    enabled = $true; interval = '1m'; from = 'now-6m'; to = 'now'
    description = $Descr; tags = @('C0015'); author = @('C0015 Lab'); threat = @($Threat)
    related_integrations = @(); required_fields = @(); setup = ''; note = $Note
    false_positives = $FP
    references = @("https://github.com/rap1p1/C0015-Conti-Detection-Lab/tree/$commit/detections",
                   'https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax')
    risk_score = $Risk; risk_score_mapping = @(); severity = $Sev; severity_mapping = @()
    output_index = ''; max_signals = 100; exceptions_list = @(); actions = @()
    meta = @{ from = '5m'; mitre_attack_version = '18'; c0015_source_commit = $commit }
    type = 'eql'; language = 'eql'; index = $Idx; query = $Query
    timestamp_field = '@timestamp'; event_category_override = 'event.category'
  }
  if ($BBlock) { $o['building_block_type'] = $BBlock }
  return $o
}

$qDir   = "$repo\detections\queries"
$sysmon = @('logs-windows.sysmon_operational-c0015*')
$sec    = @('logs-system.security-c0015*')

# Load queries for R12-R20 (bundle r12-r20) and R01-R11 (bundle r01-r11).
$ids412 = 'r12-powershell-nested-cmd-launching-discovery','r13-share-enumeration-commands','r14a-network-logon-by-user','r14b-elevated-privileges-assigned-to-user','r15-lsass-credential-access','r16-admin-share-remote-file-write','r17-wmiprvse-spawns-process-loading-unsigned-module','r18-proxy-spawned-powershell-egress','r19-rdp-interactive-logon','r20-portable-remote-access-tool','r22-ransomware-note-class','r23-note-spread-distinct-paths','r24-transfer-tool-egress'
$q = @{}
foreach ($r in $ids412) { $q[$r] = (Get-Content -LiteralPath "$qDir\$r.eql" -Raw).Trim() }
$q1 = @{}
foreach ($r in (Get-ChildItem -LiteralPath $qDir -File | Where-Object { $_.Name -match '^r(0\d|1[01])-' } | Select-Object -ExpandProperty BaseName)) {
  $q1[$r] = (Get-Content -LiteralPath "$qDir\$r.eql" -Raw).Trim()
}

$rules = @()

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R12 | PowerShell-Driven Discovery via Nested CMD' `
  -Descr 'Detects the direct discovery chain powershell -> cmd.exe -> discovery tool (net/tasklist/nltest/whoami/systeminfo/arp/wmic/ipconfig) anchored by entity - the beacon discovery batch (S4). Tree shapes with two CMD layers are covered by R10+R11 correlation, not by this rule.' `
  -Note '## Scope

S4 operator discovery (T1057/T1018/T1016/T1069/T1482) when the session beacon runs the runbook batch. Building block: ON - correlate with R10/R11 for the full chain.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, look-back 5m. Sequence of 2 events (powershell -> cmd -> discovery), maxspan 30s, joined by process.entity_id / parent.entity_id within the same host.id.

## Investigation

1. Reconstruct the process chain powershell -> cmd -> tool and compare it with the C2-SIM task results for the session.
2. Distinguish a beacon discovery batch (several commands within seconds) from occasional legitimate administration.' `
  -Sev low -Risk 21 -FP @('Administrator manually running whoami/net in a console; legitimate scripts performing discovery.') `
  -Threat (Tech $tDiscov 'T1057' 'Process Discovery') -Idx $sysmon -Query $q['r12-powershell-nested-cmd-launching-discovery'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R13 | Share Enumeration via net view or Get-SmbShare' `
  -Descr 'Detects share enumeration through command-line classes: net view (net.exe/net1.exe) or PowerShell calling Get-SmbShare (S5, T1135). net use sessions are not treated as share discovery.' `
  -Note '## Scope

S5 share enumeration; a net use against a share is a precursor to lateral movement (S7).

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, look-back 5m.

## Investigation

Inspect the surrounding command batch to determine context; correlate net use entries with subsequent logons (R14a).' `
  -Sev low -Risk 21 -FP @('Periodic share checks by administrators.') `
  -Threat (Tech $tDiscov 'T1135' 'Network Share Discovery') -Idx $sysmon -Query $q['r13-share-enumeration-commands'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R14a | Network Logon by Non-System Account' `
  -Descr 'Detects network logon (Security 4624 LogonType 3) by a real account - an authentication signal observed before the WMI/SMB hops (S7/S8b). Does not by itself prove explicit-credential use or account abuse.' `
  -Note '## Scope

S7 authentication signal. Requires the Logon/Logoff audit policy (enabled by default for success).

## Data and schedule

Security channel, index logs-system.security-c0015*. Interval 1m, look-back 5m. winlog.logon.id is not populated for 4624 (SubjectLogonId=0x0) - correlate 4624 with 4672 via TargetLogonId/SubjectLogonId manually, within the same host only.

## Investigation

Match source (SubjectUserName/WorkstationName) and target; a Type-3 logon with an administrative account preceding WMI/SMB activity indicates lateral movement.' `
  -Sev low -Risk 21 -FP @('Legitimate network logons (backup agents, admin tools, scheduled tasks with stored credentials).') `
  -Threat (Tech $tDefEv 'T1078' 'Valid Accounts') -Idx $sec -Query $q['r14a-network-logon-by-user'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R14b | Elevated Privileges Assigned to Non-System Account' `
  -Descr 'Detects Security 4672 (special privileges assigned to a new logon) for a real account - elevated-login context complementary to R14a. Context only: privilege assignment does not prove privilege-escalation behavior.' `
  -Note '## Scope

S7/S8b: elevated logon(s) used for WMI/SMB administration. Building block: ON - combine with R14a for the network-logon + special-privileges story.

## Data and schedule

Security channel, index logs-system.security-c0015*. Interval 1m, look-back 5m.

## Investigation

A 4672 immediately before wmiprvse->rundll32 (R17) on the same host completes the lateral-movement chain.' `
  -Sev medium -Risk 47 -FP @('Legitimate admin console/RDP logons also produce 4672.') `
  -Threat (Tech $tDefEv 'T1078' 'Valid Accounts') -Idx $sec -Query $q['r14b-elevated-privileges-assigned-to-user'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R15 | LSASS Access with Credential-Access Grant' `
  -Descr 'Detects OpenProcess on lsass.exe with a credential-access access mask (0x1010/0x1418/0x1fffff) from a non-system source via Sysmon E10 (S7b, T1003.001).' `
  -Note '## Scope

S7b credential-access surface. System/ambient sources (wininit/csrss/services/svchost/MsMpEng/Registry/wmiprvse) and query-info-only grants (0x1000/0x101000) are excluded. E10 access alone does not prove credential extraction.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, look-back 5m.

## Investigation

Identify the source process (name/entity/account); join its E1 for the command line; look for decoy/dump files (E11 lsass*.dmp) as confirmation context.' `
  -Sev medium -Risk 47 -FP @('AV/EDR or administration tools (ProcDump, Process Explorer) legitimately touching lsass.') `
  -Threat (Tech $tCred 'T1003' 'OS Credential Dumping' 'T1003.001' 'LSASS Memory') -Idx $sysmon -Query $q['r15-lsass-credential-access'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R16 | Admin Share Access (SMB)' `
  -Descr 'Detects access to admin shares (C$/ADMIN$) recorded by Security 5145 - an access check whose strongest instrument is the S8a tool handoff (T1570). Requires the Detailed File Share audit policy; the predicate does not distinguish read, write or result outcomes.' `
  -Note '## Scope

S8a lateral tool transfer. Sysmon E11 on the SMB target does not keep UNC path/user information, so Security 5145 is the authoritative source. The rule matches share/path only - it is an access indicator, not a write-specific detector.

## Data and schedule

Security channel, index logs-system.security-c0015*. Interval 1m, look-back 5m. ShareName values carry a \\* prefix - the pattern uses "*\\C$".

## Investigation

Verify account, share and relative path; correlate with R14a (network logon) via logon id; match the written file with E11 on the target.' `
  -Sev low -Risk 21 -FP @('Legitimate backup/administration copies over admin shares.') `
  -Threat (Tech $tLatMv 'T1570' 'Lateral Tool Transfer') -Idx $sec -Query $q['r16-admin-share-remote-file-write'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R17 | WMI-Spawned Process Loading an Unsigned Module' `
  -Descr 'Detects the WMI pivot: wmiprvse.exe spawns a process which loads an unsigned module (E1 then E7, joined by entity) - the S8b signature (T1047 + T1218.011).' `
  -Note '## Scope

S8b WMI remote process creation ending in the DLL surrogate. E7 events carry event.category=library, so the second step uses [any where event.code=="7"].

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Sequence joined by process.entity_id, maxspan 60s.

## Investigation

Verify E1 (parent=wmiprvse, integrity level) -> E7 (Signed=false, hash) -> E11 marker -> new beacon -> E3 egress (R18); correlate with the logon pair (R14a/R14b) in the same window.' `
  -Sev high -Risk 73 -FP @('Software installers using WMI and loading unsigned drivers/modules (rare).') `
  -Threat (Tech $tExec 'T1047' 'Windows Management Instrumentation') -Idx $sysmon -Query $q['r17-wmiprvse-spawns-process-loading-unsigned-module'] -BBlock ''

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R18 | Proxy-Spawned PowerShell Making an Egress Connection' `
  -Descr 'Detects PowerShell spawned by rundll32/regsvr32 (signed-proxy) making an egress connection (E1 then E3, joined by entity) - the second-session beacon (S9, T1071.001).' `
  -Note '## Scope

S9 second session established by the DLL surrogate. E3 direction=egress with a non-empty destination.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Sequence joined by process.entity_id, maxspan 120s (E3 timestamps lag E1 by 2-3s).

## Investigation

Verify rundll32 -> powershell -> egress; compare timestamps with the server-side receipt (ART-07-01); a regular polling interval to a high port is a beacon signature.' `
  -Sev high -Risk 73 -FP @('COM/plugins legitimately starting PowerShell from rundll32 (rare).') `
  -Threat (Tech $tC2 'T1071' 'Application Layer Protocol' 'T1071.001' 'Web Protocols') -Idx $sysmon -Query $q['r18-proxy-spawned-powershell-egress'] -BBlock ''

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R19 | RDP Interactive Logon by Non-System Account' `
  -Descr 'Detects RDP interactive logon (Security 4624 LogonType 10) by a real account - the day-2 RDP movement of the campaign (S12, T1021.001).' `
  -Note '## Scope

S12 remote desktop movement. Requires the Logon/Logoff audit policy (success) and the Other Logon/Logoff Events subcategory for 4778/4779 session events. Note: LogonType 3/4 alone (network/batch) do not prove a successful interactive RDP session; only Type 10 (RemoteInteractive) does.

## Data and schedule

Security channel, index logs-system.security-c0015*. Interval 1m, look-back 5m.

## Investigation

Confirm the source IP (winlog.event_data.IpAddress) and correlate the TargetLogonId with R14b; an out-of-hours type-10 logon on a server host is a strong lateral-movement signal.' `
  -Sev medium -Risk 47 -FP @('Legitimate IT remote administration over RDP.') `
  -Threat (Tech $tLatMv 'T1021' 'Remote Services' 'T1021.001' 'Remote Desktop Protocol') -Idx $sec -Query $q['r19-rdp-interactive-logon'] -BBlock 'default'

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R20 | Portable Tool Dropped into Non-Standard Location then Executed' `
  -Descr 'Detects a portable tool dropped into a non-standard location (Videos or drive root) and later executed - E11 then E1 sequence (S13). Two tool classes with distinct MITRE mappings: remote desktop software (AnyDesk/RustDesk/TeamViewer, T1219.002 Remote Desktop Software) and process-administration tooling (ProcessHacker). Host-level correlation - the rule does not prove the executed binary is the dropped file.' `
  -Note '## Scope

S13 tool deployment mirroring the report (AnyDesk under Videos\, ProcessHacker at C:\ root). The sequence joins by host.name only - it does not prove that the executed binary is the dropped file; treat as correlation.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Sequence of 2 events (drop then run), maxspan 10m, joined by host.name.

## Investigation

Confirm the binary hash against vendor signatures; check the tool''s connection targets (E3) - public relays versus lab-local listeners; correlate with R15 if the tool touches lsass.' `
  -Sev medium -Risk 47 -FP @('Users manually installing legitimate remote-control software.') `
  -Threat (Tech $tC2 'T1219' 'Remote Access Software' 'T1219.002' 'Remote Access Software') -Idx $sysmon -Query $q['r20-portable-remote-access-tool','r22-ransomware-note-class','r23-note-spread-distinct-paths','r24-transfer-tool-egress'] -BBlock 'default'

# ---------------------------------------------------------------------------
function New-ThresholdRule {
  param([string]$Name, [string]$Descr, [string]$Note, [string]$Query, [string[]]$GroupBy,
        [int]$Value, [string]$CardField, [int]$CardValue, [string]$Sev, [int]$Risk,
        [object]$Threat, [string[]]$Idx)
  $hash = ([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Name)) |
           ForEach-Object { $_.ToString('x2') }) -join ''
  $uuid = '{0}-{1}-4{2}-8{3}-{4}' -f $hash.Substring(0,8), $hash.Substring(8,4),
          $hash.Substring(12,3), $hash.Substring(15,3), $hash.Substring(18,12)
  $o = [ordered]@{
    id = $uuid; rule_id = $uuid; name = $Name; immutable = $false; version = 1; revision = 0
    updated_at = $now; updated_by = 'elastic'; created_at = $now; created_by = 'elastic'
    enabled = $true; interval = '1m'; from = 'now-10m'; to = 'now'
    description = $Descr; tags = @('C0015'); author = @('C0015 Lab'); threat = @($Threat)
    related_integrations = @(); required_fields = @(); setup = ''; note = $Note
    false_positives = @('Legitimate recovery instructions dropped on the same host.')
    references = @("https://github.com/rap1p1/C0015-Conti-Detection-Lab/tree/$commit/detections",
                   'https://www.elastic.co/docs/reference/query-languages/query-language')
    risk_score = $Risk; risk_score_mapping = @(); severity = $Sev; severity_mapping = @()
    output_index = ''; max_signals = 100; exceptions_list = @(); actions = @()
    meta = @{ from = '5m'; mitre_attack_version = '18'; c0015_source_commit = $commit }
    type = 'threshold'; language = 'kuery'; index = $Idx; query = $Query
    threshold = @{ field = $GroupBy; value = $Value; cardinality = @(@{ field = $CardField; value = $CardValue }) }
    timestamp_field = '@timestamp'; event_category_override = 'event.category'
  }
  return $o
}
# ---------------------------------------------------------------------------
# Coverage additions (2026-10-02): impact (R22/R23) and transfer (R24).
# ---------------------------------------------------------------------------
$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R22 | Potential Ransomware Note Creation' `
  -Descr 'Detects creation of ransom-note-class files (README*/DECRYPT*/HOW_TO*/READ_ME*/RECOVER* .txt) via Sysmon E11 (S14 impact precursor). A single note is an initial signal only - investigate with process/entity/path. Naming reflects a potential-impact signal, not confirmed encryption.' `
  -Note '## Scope

S14 impact-preparation signal. Building block: ON. Retains process/entity/path for triage.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, look-back 5m.

## Interpretation

A single README-like file is a weak signal; combine with R23 (note spread) and the E11 sweep. E11 covers file create/overwrite; renames appear as delete+create pairs and are only partially observed (no delete auditing).' `
  -Sev low -Risk 21 -FP @('Legitimate README/recovery instruction files.') `
  -Threat (Tech $tExec 'T1486' 'Data Encrypted for Impact') -Idx $sysmon -Query $q['r22-ransomware-note-class'] -BBlock 'default'

$rules += New-ThresholdRule `
  -Name 'C0015 | R23 | Note Spread with Same-Process Context' `
  -Descr 'Alerting: the same host+process creates ransom-note-class files in at least 3 DISTINCT paths within 10 minutes (threshold cardinality on file.path). Counts distinct paths - repeated writes of one note do not count as spread. Detects the lab impact pattern (notes across corpus dirs) while tolerating a single benign note. Names the signal as POTENTIAL impact.' `
  -Note '## Scope

S14 impact-detection. Alerting (not a building block). Threshold rule: group by host.name + process.name, require 3 distinct file.path values in the window. Baseline: the bounded impact run writes one note per corpus directory (>=3 dirs); a single note (1-2 paths) does not fire.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, window 10m. Query filters E11 note-class names.

## Interpretation

Distinct-path cardinality avoids counting repeated writes to one note. The process context (name, parent, path) is retained for triage; this is a potential-impact signal, not a proof of encryption.' `
  -Query (Get-Content -LiteralPath "$qDir\r23-note-spread-distinct-paths.eql" -Raw).Trim() `
  -GroupBy @('host.name','process.name') -Value 1 -CardField 'file.path' -CardValue 3 `
  -Sev high -Risk 73 -Threat (Tech $tExec 'T1486' 'Data Encrypted for Impact') -Idx $sysmon

$rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) `
  -Name 'C0015 | R24 | Transfer Tool Egress' `
  -Descr 'Detects a bulk-transfer tool (rclone/rsync/azcopy) starting and then making an egress connection (E1 then E3, entity join) - the S11 exfiltration behavior (T1567.002 surrogate; real rclone). Evidence-adjacent: receipts remain the authoritative transfer proof.' `
  -Note '## Scope

S11 transfer to the internal sink. Building block: ON. E3 must be owned by the same entity; destination port >= 1024.

## Data and schedule

Sysmon Operational, index logs-windows.sysmon_operational-c0015*. Sequence joined by host.name + process.entity_id, maxspan 5m.

## Interpretation

rclone executed with transfer flags (--transfers/--bwlimit) reaching the sink is the campaign signal; receipts (ART-09-01) verify file equality independently.' `
  -Sev low -Risk 21 -FP @('Legitimate backup/transfer tooling (rclone to trusted endpoints).') `
  -Threat (Tech $tC2 'T1567' 'Exfiltration Over Web Service' 'T1567.002' 'Exfiltration to Cloud Storage') -Idx $sysmon -Query $q['r24-transfer-tool-egress'] -BBlock 'default'
# S1-S3 rules (R01-R11) - same metadata shape, English notes, sysmon index.
# ---------------------------------------------------------------------------
$s3rules = @()
$specs = @(
  @{ id='r01-office-spawns-script-host-shell'; name='C0015 | R01 | Office Spawning a Script Host or Shell';
     desc='Detects an Office process (WINWORD/EXCEL/POWERPNT) spawning a script host or shell (mshta/cmd/powershell) via Sysmon E1 - the macro hand-off of the entry phase (S1, T1204.002/T1059.005).';
     note='## Scope`n`nS1 initial access: the document macro launches the script host. Building block: ON.`n`n## Data and schedule`n`nSysmon Operational, index logs-windows.sysmon_operational-c0015*. Interval 1m, look-back 5m.`n`n## Investigation`n`nConfirm the parent is the Office process and the child is a script interpreter; the chain continues with R02/R07.';
     threat=(Tech $tExec 'T1059' 'Command and Scripting Interpreter' 'T1059.005' 'Visual Basic') },
  @{ id='r02-script-host-spawning-proxy-loader'; name='C0015 | R02 | Script Host Spawning Regsvr32 or Rundll32';
     desc='Detects mshta/wscript/cscript spawning regsvr32 or rundll32 (E1) - the transition from the HTA bootstrap to the signed-proxy loader (S1, T1218.010/T1218.011).';
     note='## Scope`n`nS1 proxy execution after the HTA runs. Building block: ON.`n`n## Investigation`n`nMatch the child command line - regsvr32 /s with a staged path feeds R03.';
     threat=(Tech $tDefEv 'T1218' 'Signed Binary Proxy Execution' 'T1218.010' 'Regsvr32') },
  @{ id='r03-proxy-loader-loading-unsigned-module'; name='C0015 | R03 | Proxy Loader Loading an Unsigned Module from a Staging Path';
     desc='Detects regsvr32/rundll32 loading an unsigned module from a staging path (E7) - the DLL surrogate load (S1, T1218.010).';
     note='## Scope`n`nS1 DLL-as-JPG load. Building block: ON.`n`n## Investigation`n`nCheck Signed=false + hash; correlate with E11 of the staged file and the subsequent beacon (R05/R06).';
     threat=(Tech $tDefEv 'T1218' 'Signed Binary Proxy Execution' 'T1218.010' 'Regsvr32') },
  @{ id='r04-script-or-proxy-staging-file-write'; name='C0015 | R04 | Script or Proxy Writing to a Staging Path';
     desc='Detects script/proxy processes writing files to staging paths via E11 - ingress staging signal (S1/S2, T1105). A file creation alone does not prove a download.';
     note='## Scope`n`nStaged file writes from script/proxy processes. The entry macro''s own writes are WINWORD-originated E11 events and fall outside this predicate - coverage claim is limited accordingly. Building block: ON.`n`n## Investigation`n`nReview the written file names and the writing process.';
     threat=(Tech $tC2 'T1105' 'Ingress Tool Transfer') },
  @{ id='r05-proxy-loader-spawning-powershell'; name='C0015 | R05 | Regsvr32 or Rundll32 Spawning PowerShell';
     desc='Detects regsvr32/rundll32 spawning powershell (E1) - the DLL surrogate hands off to the session beacon (S2, T1218.010).';
     note='## Scope`n`nS2 beacon launch. Building block: ON.`n`n## Investigation`n`nJoin the child entity with E3 egress (R06) to confirm the C2 callback.';
     threat=(Tech $tExec 'T1059' 'Command and Scripting Interpreter' 'T1059.001' 'PowerShell') },
  @{ id='r06-script-host-network-egress'; name='C0015 | R06 | Script Host Network Egress';
     desc='Detects a script host (powershell/mshta/wscript) initiating an egress connection (E3) - the beacon callback channel (S2-S3, T1071.001). The connection itself does not prove HTTP or C2. Suppressed by entity to tolerate the polling loop.';
     note='## Scope`n`nBeacon C2 traffic. Building block: ON; suppression (entity, 5m) keeps the polling loop from flooding.`n`n## Investigation`n`nFilter by destination port/interval; regular polling to one endpoint is the session signature.';
     threat=(Tech $tC2 'T1071' 'Application Layer Protocol' 'T1071.001' 'Web Protocols') },
  @{ id='r07-office-to-mshta-to-proxy-loader'; name='C0015 | R07 | Office to Mshta to Proxy Loader';
     desc='Sequence: Office -> mshta -> regsvr32/rundll32 (E1 chain, entity join) - the complete entry hand-off (S1).';
     note='## Scope`n`nS1 three-step chain. Building block: ON.`n`n## Investigation`n`nA full match is the entry signature; partial matches still worth review.';
     threat=(Tech $tDefEv 'T1218' 'Signed Binary Proxy Execution' 'T1218.005' 'Mshta') },
  @{ id='r08-unsigned-module-load-to-powershell'; name='C0015 | R08 | Unsigned Module Load Followed by a PowerShell Child';
     desc='Detects a process that loads an unsigned module (E7) and then spawns powershell (E1) - loader-to-beacon hand-off (S1/S2). The predicate does not imply process injection.';
     note='## Scope`n`nS1/S2 unsigned-library hand-off. Building block: ON.`n`n## Investigation`n`nConfirm module hash and the child entity; chain into R06/R09.';
     threat=(Tech $tExec 'T1059' 'Command and Scripting Interpreter' 'T1059.001' 'PowerShell') },
  @{ id='r09-proxy-spawned-powershell-network-egress'; name='C0015 | R09 | Proxy-Spawned PowerShell Making a Network Connection';
     desc='Detects powershell spawned by a signed proxy making a network connection (E1 then E3, entity join) - beacon callback (S2-S3).';
     note='## Scope`n`nS2-S3 callback after proxy hand-off. Building block: ON.`n`n## Investigation`n`nSame entity vs R18 (which adds the rundll32/regsvr32 parent); treat as the session indicator.';
     threat=(Tech $tC2 'T1071' 'Application Layer Protocol' 'T1071.001' 'Web Protocols') },
  @{ id='r10-powershell-spawning-nested-cmd'; name='C0015 | R10 | PowerShell Spawning Nested CMD Processes';
     desc='Detects PowerShell spawning nested cmd.exe - outer and inner CMD layers (E1) - the beacon command-execution pattern (S4).';
     note='## Scope`n`nS4 task execution. Building block: ON; suppression (host+entity, 5m).`n`n## Investigation`n`nNested cmd from the beacon entity is expected during discovery batches; isolate large bursts.';
     threat=(Tech $tExec 'T1059' 'Command and Scripting Interpreter' 'T1059.001' 'PowerShell') },
  @{ id='r11-nested-cmd-launching-discovery-tool'; name='C0015 | R11 | Nested CMD Launching a Discovery-Capable Tool';
     desc='Detects cmd.exe (nested) launching a discovery-capable tool (net/nltest/whoami/tasklist) via E1 - the discovery batch (S4, T1057/T1069 etc.).';
     note='## Scope`n`nS4 discovery. Building block: ON; suppression (host+entity, 5m).`n`n## Investigation`n`nCombine with R10/R12 for the full powershell->cmd->tool chain.';
     threat=(Tech $tDiscov 'T1057' 'Process Discovery') }
)
foreach ($sp in $specs) {
  $s3rules += New-Rule -Id ([guid]::NewGuid()) -RuleId ([guid]::NewGuid()) -Name $sp.name -Descr $sp.desc `
    -Note ($sp.note -replace "`n", "`r`n") -Sev low -Risk 21 -FP @('Legitimate use of the same living-off-the-land binaries.') `
    -Threat $sp.threat -Idx $sysmon -Query $q1[$sp.id] -BBlock 'default'
}
$s3supp = @{
  'C0015 | R06 | Script Host Network Egress'                          = @{ group_by = @('process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R10 | PowerShell Spawning Nested CMD Processes'             = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R11 | Nested CMD Launching a Discovery-Capable Tool'        = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
}
$s3rules = foreach ($r in $s3rules) { if ($s3supp.ContainsKey([string]$r.name)) { $r['alert_suppression'] = $s3supp[[string]$r.name] }; $r }

# ---------------------------------------------------------------------------
# Alert suppression (R12-R20 bundle) to absorb sweep duplication.
# ---------------------------------------------------------------------------
$supp = @{
  'C0015 | R06 | Script Host Network Egress'                                    = @{ group_by = @('process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R10 | PowerShell Spawning Nested CMD Processes'                       = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R11 | Nested CMD Launching a Discovery-Capable Tool'                  = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R12 | PowerShell-Driven Discovery via Nested CMD'                     = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R13 | Share Enumeration via net view or Get-SmbShare'                 = @{ group_by = @('process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R14a | Network Logon by Non-System Account'                           = @{ group_by = @('host.name', 'winlog.event_data.TargetLogonId'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R14b | Elevated Privileges Assigned to Non-System Account'                  = @{ group_by = @('host.name', 'winlog.event_data.SubjectLogonId'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R16 | Admin Share Access (SMB)'                                           = @{ group_by = @('host.name', 'winlog.event_data.SubjectLogonId', 'winlog.event_data.ShareName'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R15 | LSASS Access with Credential-Access Grant'                      = @{ group_by = @('process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R17 | WMI-Spawned Process Loading an Unsigned Module'                 = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
  'C0015 | R18 | Proxy-Spawned PowerShell Making an Egress Connection'           = @{ group_by = @('host.name', 'process.entity_id'); duration = @{ value = 5; unit = 'm' } }
}
$rules = foreach ($r in $rules) { if ($supp.ContainsKey([string]$r.name)) { $r['alert_suppression'] = $supp[[string]$r.name] }; $r }

# ---------------------------------------------------------------------------
# Fail-fast validation: non-empty queries, named rules, unique ids.
# ---------------------------------------------------------------------------
$allrules = @($s3rules) + @($rules)
foreach ($r in $allrules) {
  if ([string]::IsNullOrWhiteSpace([string]$r.query)) { throw "empty query for rule: $($r.name)" }
  if ([string]::IsNullOrWhiteSpace([string]$r.name)) { throw "rule without name" }
}
$ids = @($allrules.rule_id)
if (($ids | Select-Object -Unique).Count -ne $ids.Count) { throw "duplicate rule_id in export" }

($s3rules | ForEach-Object { $_ | ConvertTo-Json -Depth 12 -Compress }) | Set-Content -LiteralPath "$repo\detections\exports\c0015-rules-r01-r11.ndjson" -Encoding UTF8
Write-Output "written S1-S3: $($s3rules.Count) rules"
($rules | ForEach-Object { $_ | ConvertTo-Json -Depth 12 -Compress }) | Set-Content -LiteralPath "$repo\detections\exports\c0015-rules-r12-r24.ndjson" -Encoding UTF8
Write-Output "written S4-S9: $($rules.Count) rules"









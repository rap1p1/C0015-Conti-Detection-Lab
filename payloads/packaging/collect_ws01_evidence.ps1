<#
.SYNOPSIS
Run on WS01 after a phase-1 simulation to collect STRUCTURED Sysmon evidence for the
run ledger (S1-S4): Event XML is parsed so correlation fields are preserved
(ProcessGuid, ParentProcessGuid, ParentProcessId, Image, CommandLine, User, LogonId,
Hashes, TargetFilename, Source/Destination IP and port, plus RecordID and UTC timestamps).
READ-ONLY (Get-WinEvent / Get-FileHash / Get-Content). No secrets: config.ini holds no
secrets (the session token is runtime-only).

Event families:
  - E1  process create  : kept when Image or ParentImage is in the lab-chain set.
  - E7  image load      : ImageLoaded under C:\Users\Public\C0015 / C:\C0015 / C:\Tools.
  - E11 file create     : TargetFilename under C:\Users\Public\C0015.
  - E3  network connect : DestinationIp 192.168.50.1 with port 8000/8080 (C2 channel).
  - E10 process access  : TargetImage lsass.exe / lab-target.exe (S7b credential-access study).

.PARAMETER ConfigPath  Path to the run config (default C:\Users\Public\C0015\config.ini).
.PARAMETER SinceMinutes Look-back window (default 30).
.PARAMETER OutPath     JSON output (default resolved under evidence\run-ledger\).
.EXAMPLE
powershell -ExecutionPolicy Bypass -File payloads/packaging/collect_ws01_evidence.ps1 -SinceMinutes 30 -OutPath C:\Users\Public\c0015-evidence.json
#>
param(
    [string]$ConfigPath = 'C:\Users\Public\C0015\config.ini',
    [int]$SinceMinutes = 30,
    [string]$OutPath = ''
)
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-$SinceMinutes)
$pub = 'C:\Users\Public\C0015'
$chainNames = 'WINWORD\.EXE|cmd\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|powershell\.exe|net\.exe|net1\.exe|nltest\.exe|tasklist\.exe|ping\.exe|whoami\.exe|wmic\.exe|mimikatz\.exe|conhost\.exe'

function Get-IniValue {
    param([string]$Path,[string]$Section,[string]$Key)
    $cur=''; $val=$null
    foreach ($ln in Get-Content -LiteralPath $Path) {
        $t=$ln.Trim()
        if ($t -match '^\[(.+)\]$') { $cur=$Matches[1] }
        elseif ($cur -eq $Section -and $t -like "$Key=*") { $val=$t.Substring($Key.Length+1) }
    }
    return $val
}

function ConvertTo-FlatEvent {
    param($ev)
    [xml]$x = $ev.ToXml()
    $sys = $x.Event.System
    $data = @{}
    if ($x.Event.EventData.Data) {
        foreach ($d in $x.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = ($d.'#text' -as [string]) } else { $data["_col$($data.Count)"] = ($d.'#text' -as [string]) }
        }
    }
    return [pscustomobject]@{
        timestamp_utc = ([string]$sys.TimeCreated.SystemTime)
        event_code    = [int][string]$sys.EventID
        record_id     = [uint64][string]$sys.EventRecordID
        computer      = [string]$sys.Computer
        fields        = $data
    }
}

$run_id = Get-IniValue $ConfigPath 'lab' 'run_id'
if (-not $run_id) { $run_id = 'UNKNOWN' }
$dllName = Get-IniValue $ConfigPath 'bootstrap' 'dll_name'
if (-not $dllName) { $dllName = 'c0015-comparefor.jpg' }
if (-not $OutPath) { $OutPath = Join-Path $PSScriptRoot "../../evidence/run-ledger/ws01-evidence-$run_id-structured.json" }
$OutPath = [IO.Path]::GetFullPath($OutPath)

$ch = 'Microsoft-Windows-Sysmon/Operational'
$families = @{ 'process_create' = 1; 'image_load' = 7; 'file_create' = 11; 'network' = 3; 'process_access' = 10 }
$result = @{}
foreach ($name in $families.Keys) {
    $id = $families[$name]
    $keep = @()
    try {
        $evs = Get-WinEvent -FilterHashtable @{LogName=$ch; Id=$id; StartTime=$since} -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $f = ConvertTo-FlatEvent $ev
            $fields = $f.fields
            $take = $false
            if ($id -eq 1) {
                $img   = [string]$fields['Image']
                $pimg  = [string]$fields['ParentImage']
                if (-not $img) { $img = [string]$fields['Image'] }
                $take = ($img -match $chainNames) -or ($pimg -match $chainNames)
            } elseif ($id -eq 7) {
                $il = [string]$fields['ImageLoaded']
                $take = ($il -match [regex]::Escape($pub)) -or ($il -match 'C:\\C0015') -or ($il -match 'C:\\Tools')
            } elseif ($id -eq 11) {
                $tf = [string]$fields['TargetFilename']
                $take = ($tf -match [regex]::Escape($pub))
            } elseif ($id -eq 10) {
                $ti = [string]$fields['TargetImage']
                $take = ($ti -match 'lsass\.exe$') -or ($ti -match 'lab-target\.exe$')
            } elseif ($id -eq 3) {
                $dip  = [string]$fields['DestinationIp']
                $dport = [string]$fields['DestinationPort']
                $take = ($dip -eq '192.168.50.1') -and ($dport -in @('8000','8080'))
            }
            if ($take) { $keep += $f }
        }
    } catch { $keep = @() }
    $result[$name] = $keep
}

$artifacts = @()
foreach ($f in (Get-ChildItem -LiteralPath $pub -File -ErrorAction SilentlyContinue)) {
    $artifacts += [pscustomobject]@{ Name=$f.Name; Path=$f.FullName; Sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash; Size=$f.Length }
}

$out = [pscustomobject]@{
    run_id        = $run_id
    host          = $env:COMPUTERNAME
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    since_utc     = $since.ToUniversalTime().ToString('o')
    config        = @{
        c2_url     = Get-IniValue $ConfigPath 'c2sim' 'c2_url'
        stage      = Get-IniValue $ConfigPath 'c2sim' 'stage'
        host_alias = Get-IniValue $ConfigPath 'c2sim' 'host_alias'
        dll_name   = $dllName
    }
    sysmon        = $result
    artifacts     = $artifacts
    notes         = 'Structured evidence: fields are raw Sysmon EventData names. Join keys: ProcessGuid=process.entity_id, ParentProcessGuid=process.parent.entity_id (same host only); use SystemTime/UtcTime (UTC) for cross-host windows. Verify ECS mapping in Elastic before asserting any field name.'
}
$dir = Split-Path $OutPath -Parent
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
Set-Content -LiteralPath $OutPath -Value ($out | ConvertTo-Json -Depth 8) -Encoding UTF8
Write-Output "structured evidence written: $OutPath"
Write-Output "  E1=$($('' + $result.process_create.Count)) E7=$($('' + $result.image_load.Count)) E11=$($('' + $result.file_create.Count)) E3=$($('' + $result.network.Count)) E10=$($('' + $result.process_access.Count)) run_id=$run_id"
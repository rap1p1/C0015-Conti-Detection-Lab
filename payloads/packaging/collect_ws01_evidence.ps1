<#
.SYNOPSIS
Run on WS01 after a phase-1 simulation to collect the evidence needed for the
run ledger: Sysmon process/image/file/network events for the S1-S3 chain plus
artifact hashes. READ-ONLY (Get-WinEvent / Get-FileHash / Get-Content). No
secrets: config.ini is not designed to hold secrets (token is runtime only).

.PARAMETER ConfigPath  Path to the run config (default C:\Users\Public\C0015\config.ini).
.PARAMETER SinceMinutes  Look-back window (default 30 minutes).
.PARAMETER OutPath     JSON output path (default <repo>\evidence\run-ledger\ws01-evidence-<runid>.json).
.EXAMPLE
powershell -ExecutionPolicy Bypass -File payloads/packaging/collect_ws01_evidence.ps1 -SinceMinutes 30
#>
param(
    [string]$ConfigPath = 'C:\Users\Public\C0015\config.ini',
    [int]$SinceMinutes = 30,
    [string]$OutPath = ''
)
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-$SinceMinutes)
$pub = 'C:\Users\Public\C0015'

function Get-IniValue {
    param([string]$Path, [string]$Section, [string]$Key)
    $cur=''; $val=$null
    foreach ($ln in Get-Content -LiteralPath $Path) {
        $t=$ln.Trim()
        if ($t -match '^\[(.+)\]$') { $cur=$Matches[1] }
        elseif ($cur -eq $Section -and $t -like "$Key=*") { $val=$t.Substring($Key.Length+1) }
    }
    return $val
}

$run_id = Get-IniValue $ConfigPath 'lab' 'run_id'
if (-not $run_id) { $run_id = 'UNKNOWN' }
$dllName = Get-IniValue $ConfigPath 'bootstrap' 'dll_name'
if (-not $dllName) { $dllName = 'c0015-comparefor.jpg' }
if (-not $OutPath) { $OutPath = Join-Path $PSScriptRoot "../../evidence/run-ledger/ws01-evidence-$run_id.json" }

$ch = 'Microsoft-Windows-Sysmon/Operational'
$sys = @(
    @{ name='process_create'; id=1 }
    @{ name='image_load';     id=7 }
    @{ name='file_create';    id=11 }
    @{ name='network';        id=3 }
)
$events = @{}
foreach ($s in $sys) {
    $found = @()
    try {
        $evs = Get-WinEvent -FilterHashtable @{LogName=$ch; Id=$s.id; StartTime=$since} -ErrorAction SilentlyContinue
        foreach ($e in $evs) {
            $msg = $e.Message
            $keep = $false
            if ($s.id -eq 1) {
                $keep = ($msg -match 'WINWORD|cmd\.exe|mshta|regsvr32|powershell')
            } elseif ($s.id -eq 7) {
                $keep = ($msg -match [regex]::Escape($pub) -or $msg -match 'C:\\C0015' -or $msg -match 'C:\\Tools')
            } elseif ($s.id -eq 11) {
                $keep = ($msg -match [regex]::Escape($pub))
            } elseif ($s.id -eq 3) {
                $keep = ($msg -match '192\.168\.50\.1:(8000|8080)')
            }
            if ($keep) {
                $found += [pscustomobject]@{
                    TimeCreated = $e.TimeCreated.ToString('o')
                    RecordId    = $e.RecordId
                    Id          = $e.Id
                    Msg         = ($msg -replace '`r|`n',' ').Substring(0, [Math]::Min(500, ($msg -replace '`r|`n',' ').Length))
                }
            }
        }
    } catch { $found = @() }
    $events[$s.name] = $found
}

$artifacts = @()
foreach ($f in (Get-ChildItem -LiteralPath $pub -File -ErrorAction SilentlyContinue)) {
    $artifacts += [pscustomobject]@{
        Name = $f.Name
        Path = $f.FullName
        Sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        Size = $f.Length
    }
}

$result = [pscustomobject]@{
    run_id   = $run_id
    host     = $env:COMPUTERNAME
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    since_utc = $since.ToUniversalTime().ToString('o')
    config   = @{
        c2_url   = Get-IniValue $ConfigPath 'c2sim' 'c2_url'
        stage    = Get-IniValue $ConfigPath 'c2sim' 'stage'
        host_alias = Get-IniValue $ConfigPath 'c2sim' 'host_alias'
        dll_name = $dllName
    }
    sysmon   = $events
    artifacts = $artifacts
    notes    = 'Sysmon refs are raw event summaries; verify in Elastic by host/channel/RecordID/time. E7 requires BALANCED/CAPTURE profile deployed.'
}
$json = $result | ConvertTo-Json -Depth 6
$dir = Split-Path $OutPath -Parent
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
Set-Content -LiteralPath $OutPath -Value $json -Encoding UTF8
Write-Output "evidence written: $OutPath"
Write-Output "  run_id=$run_id  E1=$($events.process_create.Count) E7=$($events.image_load.Count) E11=$($events.file_create.Count) E3=$($events.network.Count)"
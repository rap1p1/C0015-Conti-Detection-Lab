<#
.SYNOPSIS
Rerun-v2 preflight via VMware Workstation vmrun — automates the one-time P0 gates on
WS01 / FS01 / Kali WITHOUT touching their consoles (phases/phase1-initial-access/rerun-v2-remote-operator-design.md §5.1).

Pattern per guest: copy a script in -> run it (admin, output redirected to a file)
-> copy the output back -> print. No interactive prompts; credentials come from a
DPAPI Export-CliXml file (payloads/packaging/make_lab_creds.ps1) or -GuestUser/-GuestPass.

IMPORTANT: vmrun needs the password on its command line (-gp). That is infrastructure
tooling (never in repo/evidence/telemetry); the value comes from the encrypted clixml,
not from any persistent log. Delete the cred file after the campaign.

Windows gates (WS01 + FS01):
  1. it.admin in local Administrators (SeDebug path)
  2. Defender: Tamper best-effort reg, ASR d1e49aac OFF, realtime OFF, exclusions
  3. WMI inbound firewall group enabled  (WS01 NEW — remote S7b operator hop)
  4. icacls C:\C0015 Everyone:F (FS01)
  5. WS01: EnableLUA=0 (+ optional -DoReboot) ; Trust Center Word VBAWarnings/AccessVBOM/ProtectedView
Kali gate: build the DLL payload (build_dll.sh + 143 surrogate) and print hashes.

Usage (run on the C2 host):
  pwsh -File payloads/packaging/preflight_vmrun.ps1 -CredFile stage/lab-credentials-admin.xml [-DoReboot]
#>
[CmdletBinding()]
param(
    [string]$Vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    [string]$Ws01 = 'E:\VM\C0015\WS01\WS01 - C0015.vmx',
    [string]$Fs01 = 'E:\VM\C0015\FS01\FS01.vmx',
    [string]$Kali = 'C:\Users\tolon\OneDrive\ドキュメント\Virtual Machines\kali-linux-2026.2-vmware-amd64.vmwarevm\kali-linux-2026.2-vmware-amd64.vmx',
    [string]$CredFile = 'stage/lab-credentials-admin.xml',   # DPAPI clixml: C0015\it.admin (Windows VMs)
    [string]$KaliUser = 'root',
    [string]$KaliPass = '',
    [switch]$DoReboot,       # reboot WS01 after EnableLUA=0
    [switch]$SkipWindows,
    [switch]$SkipKali
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Vmrun)) { throw "vmrun not found: $Vmrun" }
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName
$credF = Join-Path $repo $CredFile
if (Test-Path $credF) { $cred = Import-CliXml $credF } else { $cred = $null }
$winUser = if ($cred) { $cred.UserName } else { '' }
$winPass = if ($cred) { $cred.GetNetworkCredential().Password } else { '' }
if (-not $winPass) { throw "no Windows guest credential (run make_lab_creds.ps1 first or pass -CredFile)" }

$tmp = 'C:\Windows\Temp'   # existing guest dir (no mkdir needed)
function VmRun {
    param([string]$Vmx, [string]$User, [string]$Pass, [string]$Prog, [string]$Args)
    Write-Host "  vmrun: $Prog $Args" -ForegroundColor DarkGray
    & $Vmrun -T ws -gu $User -gp $Pass runProgramInGuest $Vmx $Prog $Args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "vmrun failed (rc=$LASTEXITCODE): $Prog $Args" }
}
function Copy-In {
    param([string]$Vmx, [string]$User, [string]$Pass, [string]$HostPath, [string]$GuestPath)
    & $Vmrun -T ws -gu $User -gp $Pass copyFileFromHostToGuest $Vmx $HostPath $GuestPath 2>&1 | Out-Null
    if (-not $?) { throw "copyFileFromHostToGuest failed" }
}
function Copy-Out {
    param([string]$Vmx, [string]$User, [string]$Pass, [string]$GuestPath, [string]$HostPath)
    & $Vmrun -T ws -gu $User -gp $Pass copyFileFromGuestToHost $Vmx $GuestPath $HostPath 2>&1 | Out-Null
    if (-not $?) { throw "copyFileFromGuestToHost failed" }
}
function Show-GuestOut {
    param([string]$HostPath, [string]$Label)
    $p = Get-Item $HostPath -ErrorAction SilentlyContinue
    if (-not $p) { Write-Host "  ${Label}: (no output file)" -ForegroundColor Yellow; return }
    Write-Host "===== $Label =====" -ForegroundColor Cyan
    Get-Content $p
}

$pre = Join-Path (Resolve-Path $PSScriptRoot) 'preflight_win.ps1'

if (-not $SkipWindows) {
    foreach ($vm in @(@{ Name = 'WS01'; Vmx = $Ws01 }, @{ Name = 'FS01'; Vmx = $Fs01 })) {
        Write-Host "`n##### PREFLIGHT $($vm.Name) #####" -ForegroundColor Green
        $outH = Join-Path $env:TEMP "preflight-$($vm.Name).out"
        # copy preflight_win.ps1 (same script, host-dependent via $env:C0015_PREFLIGHT_HOST)
        Copy-In $vm.Vmx $winUser $winPass $pre "$tmp\preflight_win.ps1"
        $cmd = "cmd.exe /c set C0015_PREFLIGHT_HOST=$($vm.Name) && powershell -NoProfile -ExecutionPolicy Bypass -File $tmp\preflight_win.ps1 > $tmp\out.txt 2>&1"
        VmRun $vm.Vmx $winUser $winPass 'cmd.exe' "/c $cmd"
        Copy-Out $vm.Vmx $winUser $winPass "$tmp\out.txt" $outH
        Show-GuestOut $outH "PREFLIGHT $($vm.Name) OUTPUT"
        if ($vm.Name -eq 'WS01' -and $DoReboot) {
            Write-Host "  rebooting WS01 (EnableLUA=0)..." -ForegroundColor Yellow
            & $Vmrun -T ws -gu $winUser -gp $winPass reset $Ws01 2>&1
            Start-Sleep 12
            Write-Host "  WS01 rebooting - cho boot xong roi kiem tra (ping). (icon: VM da reset)" -ForegroundColor Yellow
        }
    }
}

if (-not $SkipKali) {
    Write-Host "`n##### PREFLIGHT KALI (build payloads) #####" -ForegroundColor Green
    $sh = Join-Path (Resolve-Path $PSScriptRoot) 'preflight_kali.sh'
    $outH = Join-Path $env:TEMP 'preflight-kali.out'
    Copy-In $Kali $KaliUser $KaliPass $sh '/tmp/c0015_preflight_kali.sh'
    VmRun $Kali $KaliUser $KaliPass '/bin/bash' '/tmp/c0015_preflight_kali.sh > /tmp/out.txt 2>&1'
    Copy-Out $Kali $KaliUser $KaliPass '/tmp/out.txt' $outH
    Show-GuestOut $outH 'KALI BUILD OUTPUT'
    # pull artifacts into the repo
    & $Vmrun -T ws -gu $KaliUser -gp $KaliPass copyFileFromGuestToHost $Kali '/root/build/out/c0015-comparefor.jpg' (Join-Path $repo 'build/out/c0015-comparefor.jpg') 2>&1 | Out-Null
    & $Vmrun -T ws -gu $KaliUser -gp $KaliPass copyFileFromGuestToHost $Kali '/tmp/c0015_143_surrogate.dll' (Join-Path $repo 'stage/ws01/c0015_143_surrogate.dll') 2>&1 | Out-Null
    $jpg = Get-Item (Join-Path $repo 'build/out/c0015-comparefor.jpg') -ErrorAction SilentlyContinue
    if ($jpg) { Write-Host "  pulled build/out/c0015-comparefor.jpg ($($jpg.Length) bytes)" }
}
Write-Host "`npreflight done. Kiem tra tung gate trong output, xong thi chay rerun (P0 bang tay chi con nhung gi script chua lam duoc)."

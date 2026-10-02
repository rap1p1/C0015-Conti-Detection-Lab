# ============================================================
# preflight_win.ps1 — rerun-v2 P0 gates, runs INSIDE WS01/FS01
# via vmrun as it.admin (host-dependent via $env:C0015_PREFLIGHT_HOST).
# Output: status lines only (stdout redirect by vmrun caller).
# ============================================================
$ErrorActionPreference = 'Continue'
$hostName = $env:C0015_PREFLIGHT_HOST
if (-not $hostName) { $hostName = $env:COMPUTERNAME }
function S { param([string]$m) Write-Output ('[preflight] {0}' -f $m) }

S "== $hostName preflight start utc=$(Get-Date -Format o) user=$env:USERNAME =="

# 1) it.admin in local Administrators
try {
    $adm = (Get-LocalGroupMember -Group Administrators -ErrorAction Stop | Select-Object -ExpandProperty Name) -join ', '
    S "admins: $adm"
    S "it.admin admin: $($adm -match 'it\.admin')"
} catch { S "admin check error: $($_.Exception.Message)" }

# 2) Defender: tamper (best effort) -> RTM off -> ASR off -> exclusions
try {
    try {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        S "tamper reg set (best effort - verify UI state; if still ON, disable manually once)"
    } catch { S "tamper reg: $($_.Exception.Message)" }
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -AttackSurfaceReductionRules_Ids 'd1e49aac-8f56-4280-b9aa-9936ba642ffc' -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess pwsh.exe,powershell.exe,cmd.exe,wmic.exe,rundll32.exe,mimikatz.exe,mshta.exe -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath C:\C0015,C:\stage,C:\Tools,C:\Users\Public\C0015,C:\ProgramData\C0015,E:\lab -ErrorAction SilentlyContinue
    $st = Get-MpComputerStatus
    S "RTM enabled: $($st.RealTimeProtectionEnabled)  ASR: $(( Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids -join ',')"
} catch { S "defender step error: $($_.Exception.Message)" }

# 3) WMI inbound firewall (WS01 NEW - operator remote S7b; FS01 kept)
try {
    Set-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -Enabled True -ErrorAction Stop
    S "WMI firewall group: Enabled"
} catch { S "WMI firewall: $($_.Exception.Message)" }

# 4) FS01: C:\C0015 + ACL
if ($hostName -eq 'FS01') {
    try {
        New-Item -ItemType Directory -Force -Path C:\C0015 | Out-Null
        icacls.exe C:\C0015 /grant Everyone:F /T 2>&1 | Out-Null
        S "C:\C0015 ready + Everyone:F"
    } catch { S "C:\C0015: $($_.Exception.Message)" }
}

# 5) WS01 only: EnableLUA=0 (reboot handled by vmrun caller) + Word Trust Center
if ($hostName -eq 'WS01') {
    try {
        $cur = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        if ($cur -ne 0) {
            Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 0 -Type DWord
            S "EnableLUA: 1 -> 0 (REBOOT REQUIRED)"
        } else { S "EnableLUA: already 0" }
    } catch { S "EnableLUA: $($_.Exception.Message)" }
    try {
        $sec = 'HKCU:\Software\Microsoft\Office\16.0\Word\Security'
        if (-not (Test-Path $sec)) { New-Item -Path $sec -Force | Out-Null }
        Set-ItemProperty $sec -Name VBAWarnings -Value 1 -Type DWord   # enable all macros
        Set-ItemProperty $sec -Name AccessVBOM -Value 1 -Type DWord    # COM injection OK
        $pv = "$sec\ProtectedView"
        if (-not (Test-Path $pv)) { New-Item -Path $pv -Force | Out-Null }
        Set-ItemProperty $pv -Name DisableInternetFilesInPV -Value 1 -Type DWord
        Set-ItemProperty $pv -Name DisableUnsafeLocationsInPV -Value 1 -Type DWord
        Set-ItemProperty $pv -Name DisableAttachmentsInPV -Value 1 -Type DWord
        S "Word Trust Center: macros enabled + ProtectedView off + AccessVBOM=1"
        $wp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winword.exe' -ErrorAction SilentlyContinue
        S "winword installed: $($null -ne $wp)"
    } catch { S "word trust center: $($_.Exception.Message)" }
}

S "== $hostName preflight end =="
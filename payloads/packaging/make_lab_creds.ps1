<#
.SYNOPSIS
Create a DPAPI-encrypted credential file (Export-CliXml) for the remote-operator
scripts (wmi_rundll32_diag.ps1, remote_operator.ps1). The password is entered at
an interactive Get-Credential prompt ONLY - it never appears on a command line,
in repo files, or in telemetry. The CliXml is bound to this user + machine
(DPAPI); stage/ is gitignored so it is never committed.

Usage (run on the C2 host, elevated not required):
  powershell -ExecutionPolicy Bypass -File payloads/packaging/make_lab_creds.ps1 -Name C0015\it.admin
#>
[CmdletBinding()]
param(
    [string]$Name = 'C0015\it.admin',
    [string]$OutFile = 'stage/lab-credentials-itadmin.xml'
)
$ErrorActionPreference = 'Stop'
$repo = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName
$out = Join-Path $repo $OutFile
New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null

Write-Host "Nhap credential cho $Name tai prompt (password khong doc lai / khong log)."
$cred = Get-Credential -Message "C0015 lab credential cho $Name (dung cho operator remote; se duoc Export-CliXml bao ve bang DPAPI)"
if (-not $cred) { throw 'no credential entered' }
$cred | Export-CliXml -Path $out
Write-Output "credential file: $out (DPAPI bound to $env:USERNAME @ $env:COMPUTERNAME)"
Write-Output "dung voi: stage/analysis/wmi_rundll32_diag.ps1 -CredFile $OutFile"
Write-Output "KHONG bao gio : xoa file nay / commit (stage/ da gitignored); xoa khi ket thuc chien dich: Remove-Item stage\lab-credentials-itadmin.xml"
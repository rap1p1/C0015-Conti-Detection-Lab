# Bootstrap and pivot DLL sources

| Source | Role |
|---|---|
| [c0015_bootstrap_dll.c](c0015_bootstrap_dll.c) | Session-1 bootstrap served as DLL-as-JPG; DllRegisterServer path under regsvr32 |
| [c0015_143_surrogate.c](c0015_143_surrogate.c) | FS01 pivot surrogate; LabEntry under rundll32 starts the second-session beacon |

Both generate benign markers and configured child execution. An initial regsvr32
flow must not be attributed to the pivot DLL simply because its source also defines
registration exports. E7 identifies which artifact the loader actually loaded.

## Retained invocation/build notes

The recorded WMI pivot uses the space-form LabEntry invocation after the earlier
comma-parsing diagnostic. These are existing templates, not newly verified commands:

```
wmic /node:FS01 process call create "C:\Windows\System32\rundll32.exe C:\C0015\c0015_143_surrogate.dll LabEntry"
```

```
cl /LD c0015_143_surrogate.c /link /OUT:c0015_143_surrogate.dll   (or use the checked-in DLL)
```

Only sources/build tooling are committed here; **there is no checked-in compiled
DLL**. The parenthetical text in the historical build snippet is explanatory, not
shell syntax. Use the packaging build tooling for its intended compiler environment.
An API process-creation ReturnValue and regsvr32 registration result are different
values and must not be conflated.

Telemetry: E1 loader/child, E7 path/signature/**`file.hash.sha256`**, and E11 marker.
Module loading in rundll32's own address space does not establish injection.

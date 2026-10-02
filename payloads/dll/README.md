# payloads/dll — DLL surrogate (rundll32)

`c0015_143_surrogate.c` + build script — the lab's `143.dll` equivalent.

## Exports

- `LabEntry` — the entry called by `rundll32.exe <dll> LabEntry` (S1 regsvr32 flow and
  S8b WMI pivot). Runtime behavior: write a marker file to a directory taken from the INI
  (`[lab] marker_dir/marker_name` from `config-phase7.ini`) and spawn the beacon from
  `[beacon] beacon_cmd` — exactly the "dll writes marker + spawns beacon" pattern of the
  campaign.
- `DllRegisterServer` — present so `regsvr32 /s` succeeds with ReturnValue 0.

## Why the space-form matters (G2)

`wmic process call create "<long cmd>"` splits arguments on **commas**, so
`...143.dll,LabEntry` returns ReturnValue 9. The verified spelling is the space form:

```
wmic /node:FS01 process call create "C:\Windows\System32\rundll32.exe C:\C0015\c0015_143_surrogate.dll LabEntry"
```

## Build

```
cl /LD c0015_143_surrogate.c /link /OUT:c0015_143_surrogate.dll   (or use the checked-in DLL)
```

Telemetry: E1 (rundll32, parent=wmiprvse in the WMI case), E7 (ImageLoad hash), E11 (marker).
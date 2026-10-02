# payloads/hta — bootstrap HTA

`bootstrap.hta` — the lab's `compareForFor.hta` equivalent (T1218.005 + T1059.007).

## Flow

1. `Get-Ini` reads `%PUBLIC%\C0015\config.ini` (no hardcoded URLs): `http_host/http_port/
   dll_name/dll_local_dir/b64_marker_name/b64_value/regsvr32_path`.
2. Downloads the DLL (masquerading as `.jpg`) via `MSXML2.XMLHTTP` (T1105) into the
   configured local dir.
3. Base64-decodes a benign marker value with MSXML `bin.base64` (no `atob()` — the report's
   HTA used the same mechanism) and writes it.
4. Executes `regsvr32.exe /s <jpg>` (T1218.010); the DLL surrogate registers and spawns
   the beacon.

## Key code

- `B64Decode` — XMLDOM `persist`/`bin.base64` decode forcing a `data` type node; the
  classic JScript HTA pattern.
- All paths/values come from the config; missing config → `exit` (control path, no chain).

Telemetry: E1 (mshta, parent=WINWORD), E3 (download `:8000`), E11 (jpg/markers).
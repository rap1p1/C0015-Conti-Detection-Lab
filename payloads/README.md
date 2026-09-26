# C0015 Lab Payloads — benign, config-driven, runnable

Mọi payload ở đây là **surrogate benign**, đọc mọi giá trị lab (URL, host, path, corpus) từ
`payloads/config/c0015.example.ini` (bản mẫu) hoặc manifest do harness tạo mỗi run — **không hardcode giá trị lab
trong code**. Không có mã độc, không injection, không credential extraction, không encryption thật.

## Danh sách payload và map vào kỹ thuật campaign gốc

| File | Vai trò trong chuỗi | Kỹ thuật (ATT&CK) | Campaign C0015 gốc (DFIR/MITRE) | Telemetry kỳ vọng |
|---|---|---|---|---|
| `docm/macro_payload.vba` | S1: macro trong `.docm`, đọc config → gọi `mshta` | T1204.002, T1059.005 | Word macro trích xuất + chạy HTA | E1 `WINWORD→cmd→mshta`; E11 |
| `hta/bootstrap.hta` | S2: VBS đọc config + decode base64 (MSXML `bin.base64` — **HTA JScript không có `atob()`**); download DLL đuôi `.jpg`; chạy `regsvr32`; JS block độc lập ghi marker | T1218.005, T1059.005/.007, T1027, T1105, T1036, T1218.010 | HTA chứa JS/VBS encoded → tải `compareForfor.jpg` về `c:\users\public` → REGSVR32 | E1 mshta/regsvr32; E11 (DLL+markers); E7 (hash, unsigned); E3 (có thể gap) |
| `dll/c0015_bootstrap_dll.c` | S2→S3: DLL benign (build ra file tên `c0015-comparefor.jpg`), export `LabEntry`/`DllRegisterServer` ghi marker + spawn beacon (command từ config) | T1218.010/.011 (proxy load), T1553.002 (unsigned observable) | Bazar loader DLL | E11 marker; E1 beacon spawn (parent = regsvr32) |
| `beacon/c0015_beacon.ps1` | S3: session-1 beacon — register → task/result loop (task allowlist từ config), public-IP check, token từ env | T1071.001 (kênh web, context), T1016, T1105 | Bazar callback + myexternalip lookup → CS beacon | E1 powershell; E3/E22 → C2-SIM; server log/receipt |
| `impact/c0015_impact.ps1` | S14: bounded impact trên corpus allowlist (Prepare/Run/Rollback/Verify) | T1486 (transform, không encrypt thật), T1083 (verify listing) | Conti batch deploy + post-impact file listing | E11/E2/E26 high-rate; note creation; restore diff |
| `config/c0015.example.ini` | Toàn bộ giá trị cấu hình (placeholder) — sao chép thành `C:\Users\Public\C0015\config.ini` trên target và điền mỗi run | — | — | — |

## Map chi tiết đoạn code → technique

| Đoạn code | Technique | Mô tả hành vi benign |
|---|---|---|
| `macro_payload.vba` — `Document_Open` → `sh.Run mshta hta` | T1204.002 / T1059.005 | User mở docm → macro thật chạy VBA; không config → không hành động (control) |
| `bootstrap.hta` — `IniGet()` đọc config | — | Không giá trị lab nào nằm trong code |
| `bootstrap.hta` — `B64Decode()` (MSXML `bin.base64`) + ghi `b64-marker.txt` | T1027 | Chuỗi base64 benign được decode = observable của obfuscation, không phụ thuộc `atob()` |
| `bootstrap.hta` — `MSXML2.XMLHTTP` GET → `ADODB.Stream` lưu `c0015-comparefor.jpg` | T1105 + T1036 | Tải DLL mang tên `.jpg` — mirror `compareForfor.jpg` |
| `bootstrap.hta` — `sh.Run regsvr32 /s <dll>` | T1218.010 | Proxy execution qua regsvr32 |
| `bootstrap.hta` — JScript block ghi `js-marker.txt` | T1059.007 | JS thực thi trong HTA (observable độc lập, không dùng atob) |
| `c0015_bootstrap_dll.c` — `LabEntry` đọc config, ghi marker | T1553.002 (unsigned) | DLL không ký tải vào regsvr32 → E7 `signed=false` |
| `c0015_bootstrap_dll.c` — `CreateProcessA(beacon_cmd)` | handoff S2→S3 | Beacon được tạo bởi bootstrap (parent chain = bằng chứng nguồn của session 1) |
| `c0015_beacon.ps1` — `Invoke-WebRequest` tới `public_ip_check_url` | T1016 | Lookup public IP qua mock nội bộ (myexternalip analog) |
| `c0015_beacon.ps1` — POST `/session/register` + GET `/task/next` + POST `/result` | T1071.001 (context) | Callback loop qua HTTP; token `S1-<16 hex>` từ env/generated — không lưu secret |
| `c0015_beacon.ps1` — `$taskMap` chạy command allowlist từ config | C2 role surrogate | Không arbitrary shell — chỉ task cố định |
| `c0015_impact.ps1` — `Test-AllowedRoot` + caps + `Rename-Item … + $ext` + note | T1486 | Transform có giới hạn trên corpus allowlist; từ chối root hệ thống/reparse/drive root |
| `c0015_impact.ps1` — `Verify` (listing + `Get-FileHash` so backup) | T1083 | Post-impact verification + khôi phục kiểm chứng |

## Build & chạy (chỉ trên máy lab của bạn, sau khi duyệt)

```powershell
# 1. Build DLL (trên Kali hoặc host có mingw) — output mang tên .jpg (T1036)
x86_64-w64-mingw32-gcc -shared -o c0015-comparefor.jpg payloads/dll/c0015_bootstrap_dll.c -lshlwapi

# 2. Config: copy mẫu, điền giá trị theo run (không đưa secret vào file này)
copy payloads\config\c0015.example.ini C:\Users\Public\C0015\config.ini   # (trên WS01)
#    + đặt HTA, DLL (c0015-comparefor.jpg), beacon vào C:\Users\Public\C0015\

# 3. Macro: dán nội dung macro_payload.vba vào module của test.docm (Document_Open)

# 4. Beacon offline test (cùng host lab):
python scripts\c2sim_v2.py --ip 127.0.0.1 --port 8080 --ledger evidence\run-ledger --log c2sim.log
powershell -NoProfile -ExecutionPolicy Bypass -File payloads\beacon\c0015_beacon.ps1 -Config <test.ini> -Once

# 5. Impact cycle (corpus dummy trong thư mục tạm, manifest do harness tạo):
.\payloads\impact\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Prepare
.\payloads\impact\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Run
.\payloads\impact\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
.\payloads\impact\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Rollback
.\payloads\impact\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
```

Các bước operator còn lại (discovery, WMI, RDP, AnyDesk) nằm trong runbook `docs/implementation-plan.md` §5 —
chúng là lệnh operator, không phải file payload.

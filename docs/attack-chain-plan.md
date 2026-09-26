# C0015 Attack-Chain Plan (v2) — Operable End-to-End Lab Chain

> **Mục đích:** biến chuỗi C0015 thành một **chuỗi lab vận hành được end-to-end**: mỗi phase thực sự thực thi
> thao tác trên máy lab, tạo telemetry tự nhiên, và tạo artifact đầu ra mà phase sau **thực sự đọc/tiêu thụ**.
> Marker/JSON/event giả không được tính là "đã thực hiện technique".
>
> **Cách đọc mỗi stage — 5 lớp bắt buộc:**
> - **Historical behavior:** C0015 được nguồn ghi nhận làm gì (kèm label + nguồn).
> - **Live lab behavior:** thao tác thực sự sẽ chạy trên máy lab và sinh telemetry tự nhiên (Windows/network/service).
> - **Surrogate behavior:** phần thay thế malware/hạ tầng thật; **cơ chế giữ lại** vs **cơ chế không giữ**.
> - **Analysis/replay-only:** phần **không thực thi**, chỉ mẫu dữ liệu/replay/phân tích.
> - **Fidelity:** `HIGH` / `PARTIAL` / `LOW` + lý do.
>
> Phase numbering canonical: **mục 10 của chính file này** (0–15 + OLD→NEW; hấp thụ `docs/phase-map.md` cũ).
> Evidence ledger: `docs/evidence-matrix-v2.md`.
> Tham chiếu kỹ thuật: `docs/handoff-contracts.md`, `docs/correlation-architecture.md`,
> `docs/payloads-and-c2.md` (C2-SIM + C2 decisions), `docs/implementation-plan.md` (blueprint/runbook). Không commit; không chạy VM activity; claim chưa xác minh giữ nguyên trạng thái.

## 0. Changelog sửa lỗi (v1 → v2)

| # | Lỗi v1 | Sửa trong v2 |
|---|---|---|
| F1 | Gán Sysmon EID 3 như bằng chứng RPC | EID 3 = **network connection** (có thể thiếu process attribution — đã gặp ở P1-B); RPC/WMI evidence dùng S4648 + S4624/4672 + **FS01 E1 `wmiprvse→rundll32`**; không dùng E3 để "chứng minh RPC" |
| F2 | Gọi WMI-Activity E19–21 là telemetry của remote process creation | **E19–21 = WMI filter/consumer/binding (T1546.003 subscription)** — KHÔNG sinh ra khi tạo process từ xa qua WMI; xóa khỏi S8/C3; trình bày đúng ở mục 4.2 |
| F3 | Macro "chứng minh" bằng process-create chain | E1 chain (WINWORD→cmd→mshta) chỉ chứng minh **WINWORD sinh process con**; macro invocation là `[INFERRED]` + trigger thủ công `[LAB-SURROGATE]`; ghi giới hạn ở S1 |
| F4 | Auth event bundle như "dữ liệu điều khiển" phase sau thực thi | Bundle S4648/4624/4672 là **evidence**; input điều khiển thật = credential pre-provisioned (operator cấp out-of-band) — sửa ở S7/H4 |
| F5 | Không phân biệt server collection/exfil vs backup server | DFIR ghi exfil **từ server khác** backup server; lab gộp vai trò vào FS01 `[LAB-SURROGATE]` → fidelity `PARTIAL`, có phương án host riêng (mục 4.8) |
| F6 | Một lượt transfer duy nhất | Timeline có **2 lượt Rclone/MEGA** (ngày 1, ngày 4), **RDP ngày 2 xen giữa** — S11a/S12/S11b (lab nén timeline, ghi rõ) |
| F7 | SANS diary 27738 mô tả như cross-check trực tiếp | Diary 27738 là **case TA551/BazarLoader tương tự — context only**, KHÔNG phải bằng chứng trực tiếp C0015; fetch thực tế = HTTP 406 (không đọc được nội dung); cập nhật mục 2 |
| F8 | Gộp "DLL injection" chung chung | Tách: D574 = rundll32 load (không injection); D8B3 = load + inject Winlogon (MITRE T1055.001); 143.dll = remote load + inject svchost (DFIR) — 3 claim riêng, nguồn/mức khác nhau (mục 5) |
| F9 | WMI command dùng `wmic` mặc định trên mọi build | `wmic.exe` bị loại khỏi Windows 11 24H2+/Server mới; nếu không có, dùng PowerShell CIM (`Invoke-CimMethod`) — **telemetry khác** (E1 parent khác, S4648 vẫn có); ghi "phụ thuộc environment" (S8) |
| F10 | Marker/DLL tồn tại như tiêu chí "kỹ thuật đã chạy" | Mọi acceptance chuyển sang bằng chứng telemetry/event + receipt; marker chỉ là phụ (S2, S9) |

## 1. Evidence labels (ánh xạ)

`[OBSERVED-C0015]` ≡ `[OBSERVED]` · `[INFERRED-C0015]` ≡ `[INFERRED]` · `[UNKNOWN-C0015]` ≡ `[UNKNOWN]` ·
`[LAB-SURROGATE]` ≡ `[LAB ASSUMPTION]` · `[SUPPLEMENTAL-LAB-TECHNIQUE]` (thêm do thiết kế lab, không phải hành vi
C0015) · `[NOT-VERIFIED-IN-REPO]` (narrative-only). Chi tiết: `docs/evidence-matrix-v2.md`.

## 2. Nguồn

| # | Nguồn | Ngày | Trạng thái truy cập | Dùng cho |
|---|---|---|---|---|
| S1 | [MITRE ATT&CK Campaign C0015](https://attack.mitre.org/campaigns/C0015/) | ATT&CK v19.2 (modified 2026-07-31; created 2022-09-29; contributor Matt Brenton, Zurich Insurance) | Fetched đầy đủ | Technique table + software refs gắn campaign |
| S2 | [The DFIR Report — CONTInuing the Bazar Ransomware Story](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/) | 2021-11-29, The DFIR Report | Fetched đầy đủ (truncated phần cuối) | Timeline, commands, IOCs, CS config |
| S3 | [SANS ISC diary 27738 (Brad Duncan)](https://isc.sans.edu/diary/27738) | DFIR dẫn 2021-11-08 | **Fetch = HTTP 406 — chưa đọc được nội dung** | **Context only:** đây là **case TA551/BazarLoader tương tự**, KHÔNG phải bằng chứng trực tiếp cho C0015 — không trích nội dung, chỉ ghi nhận DFIR nói "very similar" |
| S4 | [Tria.ge sandbox 210803-w15fxk72ns](https://tria.ge/210803-w15fxk72ns) | 2021-08-03 | Không tải được (JS) | S2 dẫn: domain gắn CS beacon sample khác (D574) — context |
| S5 | [Red Canary — Rundll32 Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/rundll32/) | Red Canary | Title only (paywall) | Detection guidance chung cho rundll32 — không trích nội dung |

**Quy tắc:** claim C0015 chỉ dựa S1/S2; nguồn khác là context/detection guidance. Không dùng tổng hợp không
nguồn; campaign Conti/Bazar khác không tự động gán sang C0015.

## 3. Historical chain summary (đã sửa timeline)

5 ngày, 8/2021 (S2). CS + operator xuất hiện trong 2 giờ đầu (S2).

1. Delivery phishing ZIP→Word: `[INFERRED-C0015]` (S2 "likely"; S1 T1566.001).
2. Macro (T1204.002) `[OBSERVED-C0015]` (S2: Word 2003 XML; user enable macro).
3. HTA encoded (T1059.005/.007, T1027) → `compareForfor.jpg` (T1036) → `c:\users\public` → **REGSVR32** (T1218.010, T1105) `[OBSERVED-C0015]` (S2).
4. Bazar (S0534) foothold: C2 64.227.65.60:443 (+161.35.147.110, 161.35.155.92, 64.227.69.92; JA3 `72a589da…`; cert GG EST/perdefue.fr), invoke Svchost, myexternalip lookup (T1016) `[OBSERVED-C0015]` (S2).
5. Transition CS (S0154): **D574.dll** rồi **D8B3.dll** qua RunDll32 "using the Svchost process" (T1218.011); **D574**: DNS volga.azureedge[.]net, **không kết nối thành công** `[OBSERVED-C0015]` (S2); **D8B3**: beacon chính, **inject vào Winlogon** (S2; S1 T1055.001), C2 82.117.252.143 (checkauj.com/five.azureedge.net); Go-compiled, invalid cert (T1553.002) `[OBSERVED-C0015]`.
6. Discovery (T1059.003, T1057, T1069.001/.002, T1482, T1018, T1124): `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all time`, `ping`; parent RunDLL32/Winlogon; copy-paste errors (runbook) `[OBSERVED-C0015]` (S2). AdFind: file write, no execution `[OBSERVED-C0015]`.
7. ShareFinder (T1135/T1074.001): Invoke-ShareFinder → `c:\ProgramData\found_shares.txt` (PowerShell invoked by WinLogon; file created by Rundll32.exe) `[OBSERVED-C0015]` (S2).
8. Target selection: backup server (high-value) `[INFERRED-C0015]` (S2: "high-value servers").
9. **Lateral movement (T1047/T1570/T1218.011)** `[OBSERVED-C0015]`: **WMIC remote process creation → rundll32 → `143.dll`** (CS beacon) trên **backup server**; beacon inject vào `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`; callback checkauj[.]com; **~9h sau RDP session qua 143.dll path** (S2).
10. Credential provenance WMI pivot: **`[UNKNOWN-C0015]`** — không suy đoán LSASS/Mimikatz.
11. Collection & exfil: re-run ShareFinder; exfil **từ một server khác** (S2: "exfiltrated data of interest from a different server"); **Rclone → MEGA ×2 lượt** (ngày 1 và ngày 4), `--bwlimit 10M --transfers 7 --multi-thread-streams 7 --max-age 2y --ignore-existing --auto-confirm` (S2/S1 T1039/T1005/T1567.002/T1030) `[OBSERVED-C0015]`.
12. **RDP (T1021.001)** `[OBSERVED-C0015]`: **ngày 2** — tới backup server qua beacon; backup console; taskmanager GUI `/4`. Cũng được ghi nhận ~9h sau khi deploy 143.dll.
13. AnyDesk (T1219.002) `[OBSERVED-C0015]`: ngày 5, `c:\users\<REDACTED>\Videos`, connection dài tới IP hợp lệ.
14. Process Hacker (root `C:\`) "likely" LSASS access: `[INFERRED-C0015]` (S2; T1003 **không** nằm trong MITRE list).
15. Impact (T1486) `[OBSERVED-C0015]`: **Conti batch** → domain-joined systems; **không chạm DC**; post-impact file listing (T1083) `[OBSERVED-C0015]`.

## 4. The chain — stages S1–S15 (5 lớp/stage)

### S1 — Entry: Word macro
- **Historical:** phishing ZIP→Word macro (delivery `[INFERRED-C0015]`; macro `[OBSERVED-C0015]`, S2/S1 T1204.002).
- **Live lab behavior:** trên WS01 mở `test.docm` (`C:\Users\duc.user\Desktop\`), **kích hoạt macro thật** (Alt+F8/debug); VBA thực thi gọi `Shell()` → sinh `cmd.exe /c mshta …`.
- **Surrogate:** macro benign, không payload độc. **Giữ:** user-execution, WINWORD→child, artifact drop. **Không giữ:** email/ZIP delivery, social engineering auto-open.
- **Analysis/replay-only:** delivery email/ZIP — không thực thi.
- **Telemetry:** E1 (WINWORD→cmd) `[OBSERVED-LAB]`; E11 (file drop). **Giới hạn (F3):** E1 chain **không chứng minh macro chạy** — chỉ chứng minh WINWORD sinh process con; macro invocation là `[INFERRED]` (trigger thủ công `[LAB-SURROGATE]`, ghi trong lịch sử commit `fe41049`).
- **Fidelity:** `HIGH` (cơ chế proxy-execution); `PARTIAL` (entry — delivery không tái hiện).
- **Acceptance:** VBA thực sự chạy (có side-effect file do macro tạo), E1 chain + run ID; ghi rõ trigger thủ công.
- **Gap:** không có mẫu email/ZIP; trigger không giống user thực.

### S2 — Bootstrap: HTA → HTTP → regsvr32 DLL
- **Historical:** HTA (JS/VBS encoded) tải `compareForfor.jpg` về `c:\users\public`, REGSVR32 execute `[OBSERVED-C0015]` (S2; T1059.005/.007/T1027/T1036/T1218.010/T1105).
- **Live lab:** từ S1: `mshta.exe C:\Users\Public\C0015\bootstrap.hta` → HTTP GET `192.168.50.100:8000` → ghi `benign.txt`, `c0015-marker.dll` → `regsvr32.exe /s c0015-marker.dll` → `DllRegisterServer()` → `dll-executed.txt` (repo P1-A/B/C verified mechanics).
- **Surrogate:** HTA/DLL benign. **Giữ:** file-path class, proxy chain, DLL load, hash liên tục. **Không giữ:** payload độc, chuỗi encoded thật.
- **Telemetry:** E1 (cmd→mshta→regsvr32), E11, **E7 ImageLoad** (unsigned DLL, path, SHA-256), E3 (P1-C = **SENSOR GAP đã biết**; server-side HTTP log độc lập), hash Kali→WS01.
- **Fidelity:** `HIGH` (mechanism); payload `SURROGATE`.
- **Acceptance (F10):** chain E1+E7+E11 cùng ProcessGuid family; hash khớp; E3 gap ghi rõ; run ID. Marker `dll-executed.txt` chỉ là **bằng chứng phụ** (DLL đã chạy export), không đơn độc.
- **Gap:** hop `mshta 6592→6032/3604` chưa nối (`[UNKNOWN]`, M-15) — phải lấy raw E1 trước khi tái lập.

### S3 — Bazar-like session 1 + transition
- **Historical:** Bazar callback C2:443, Svchost invoke, myexternalip lookup (T1016); D574/D8B3 qua RunDll32; D8B3→Winlogon; CS C2 82.117.252.143 `[OBSERVED-C0015]` (S2).
- **Live lab:** trên WS01 chạy **agent/dll surrogate** (bounded, benign): (a) public-IP lookup → HTTP GET mock `192.168.50.1:8001` (`public-ip.txt` = 203.0.113.77), (b) callback định kỳ → C2-SIM `POST /session/register?stage=phase3&host=WS01`, (c) GET task / POST result (task allowlist cố định).
- **Surrogate:** C2-SIM v2 (`docs/payloads-and-c2.md` §2.1/§6) thay Bazar/CS C2. **Giữ:** outbound callback, session registration, public-IP query, task/result loop. **Không giữ:** HTTPS/JA3/cert profile, sleep 60s/jitter 37, Malleable C2 URI, injection Winlogon.
- **Analysis/replay-only:** D574 (DNS-only không kết nối) — mô tả tài liệu, không chạy.
- **Telemetry:** E1 (agent), E3/E22 → C2-SIM/mock (attribution caveat như P1-B), server log, session receipt.
- **Fidelity:** `PARTIAL` (protocol); mechanism callback `HIGH`.
- **Acceptance:** session-1 receipt server-side + ≥1 callback cycle + run ID.
- **Gap:** receiver cho WS01 chưa tồn tại (c2sim hiện nhận FS01/phase4) — viết theo `docs/payloads-and-c2.md` §6 (đã implement `scripts/c2sim_v2.py`).

### S4 — Discovery LOLBins
- **Historical:** `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `net view /all time`, `ping` `[OBSERVED-C0015]` (S2; T1059.003/T1057/T1069/T1482/T1018/T1124).
- **Live lab:** từ session 1 (WS01), chạy **đúng các lệnh trên** bằng cmd.exe/native tools.
- **Surrogate:** không — native commands (mechanism trùng lịch sử).
- **Telemetry:** E1 từng lệnh (parent = agent), E3 (kết nối tới DC01:389/445 — **E3 là network connection, không phải "event RPC"**, F1), timing burst. T1016/T1018 cũ: `[NOT-VERIFIED-IN-REPO]`/`CONTRADICTED`.
- **Fidelity:** `HIGH`.
- **Acceptance:** ≥4 behavior family DETECTED (C1) + run ID.
- **Gap:** quyết định target nằm ở S6 (orchestration), không ở lệnh.

### S5 — ShareFinder → found_shares
- **Historical:** Invoke-ShareFinder → `c:\ProgramData\found_shares.txt` (tạo bởi Rundll32.exe) `[OBSERVED-C0015]` (S2; T1135/T1074.001).
- **Live lab:** WS01 chạy PowerShell (hoặc `net view`) enumerate shares **read-only**; ghi `C:\ProgramData\found_shares.txt` (mirror path `[LAB-SURROGATE]`) + `ART-04-01` JSON.
- **Surrogate:** không dùng PowerView thật; output artifact giữ hình dạng lịch sử.
- **Telemetry:** E1 (powershell.exe), E11 (file write), S5145 nếu probe share.
- **Fidelity:** `HIGH` (output artifact); tool `SURROGATE`.
- **Acceptance:** artifact liệt kê share (FS01\Finance readable) + run ID.

### S6 — Decision + target manifest (orchestration)
- **Historical:** operator chọn backup server (high-value) `[INFERRED-C0015]` (S2).
- **Live lab:** orchestration script (Kali/host) **đọc thật `ART-04-01`** → chọn target theo rule (share readable + high-value) → **ghi thật `ART-04-02`** (target=FS01, reason, auth account, allowed actions). Không hard-code: nếu không có share readable → không tạo manifest → chain dừng.
- **Surrogate/SUPPLEMENTAL:** target-manifest + orchestration layer (`[SUPPLEMENTAL-LAB-TECHNIQUE]` — quyết định thật không thể quan sát).
- **Telemetry:** orchestration ledger (không phải endpoint event).
- **Fidelity:** `PARTIAL` (quyết định thật không ghi nhận được).
- **Acceptance:** `ART-04-02.target.host` suy ra từ nội dung `ART-04-01` (log selection_reason) + run ID.
- **Control cases:** không tìm thấy target → `NOT RUN`; nhiều target → chọn theo rule; quyền từ chối → `DENIED` (kiểm ở S7).

### S7 — Auth context
- **Historical:** provenance credential WMI pivot `[UNKNOWN-C0015]`.
- **Live lab:** operator dùng `C0015\it.admin` **pre-provisioned** (quyền đọc FS01, không DA) — credential cấp out-of-band `[LAB-SURROGATE]`; chạy 3 control: `duc.user` → denied, `it.admin` → allowed, revoked → denied.
- **Surrogate:** identity provision sẵn; **không** mô phỏng thu thập credential.
- **Telemetry (F4 — EVIDENCE, không phải dữ liệu điều khiển):** S4648 (WS01), S4624 Type3 + S4672 (FS01), S4625 (control). Bundle `ART-05-01` **chứng minh** credential đã được dùng; phase sau (S8) thực thi BẰNG credential (input điều khiển thật do operator cấp), bundle chỉ là bằng chứng kết quả.
- **Fidelity:** mechanism `HIGH`; provenance `[UNKNOWN-C0015]` không tái hiện.
- **Acceptance:** denied/allowed/denied đúng + LogonId liên kết trong `ART-05-01` + run ID.

### S8 — WMI remote process creation
- **Historical:** **WMIC remote process creation → rundll32 → `143.dll`** trên backup server `[OBSERVED-C0015]` (S2; T1047/T1570/T1218.011).
- **Live lab:** trên WS01 (session 1 + `it.admin`): `wmic /node:FS01 /user:C0015\it.admin process call create "rundll32.exe C:\C0015\c0015_143_surrogate.dll,<export>"` **nếu `wmic` tồn tại trên build đó (F9)**; nếu không (Windows 11 24H2+/Server mới), dùng PowerShell `Invoke-CimMethod -ClassName Win32_Process -MethodName Create` — **telemetry khác** (E1 parent khác, S4648 vẫn có), ghi rõ environment. FS01 thực thi rundll32 trong context `it.admin`.
- **Surrogate:** DLL benign; giữ cơ chế WMI remote process + rundll32 proxy.
- **Telemetry (F1/F2):** WS01: S4648, E3 (connection WS01→FS01 — **network connection, không chứng minh RPC**; attribution có thể rỗng), S5156 (tùy chọn). FS01: **S4624 Type3 + S4672 + S4688 (nếu audit) + E1 `wmiprvse.exe → rundll32.exe` (bằng chứng then chốt)** + E7 + E11. **KHÔNG kỳ vọng E19–21** (xem 4.2).
- **Fidelity:** `HIGH` mechanism; phụ thuộc build (wmic/CIM).
- **Acceptance:** 4 câu completion gate (process trên FS01, identity, process nào + DLL hash, callback từ FS01 — callback ở S9) cùng run ID.
- **Gap:** event/field phụ thuộc Windows version — verify trên environment (không khẳng định mọi máy sinh cùng event).

### S9 — `143.dll` branch → session 2 (safe, không injection)
- **Historical:** 143.dll = CS beacon inject vào `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`; callback checkauj.com; ~9h sau RDP `[OBSERVED-C0015]` (S2).
- **Live lab (tách injection):** DLL benign được rundll32 nạp trên FS01 (S8) sẽ: (1) POST `/session/register` {host=FS01, stage=phase7-session2, token tự sinh} → C2-SIM, (2) GET `/task/next` → task **cố định benign** (`T-DISCOVER-CORPUS`), (3) thực thi task (đọc danh sách file corpus — chỉ metadata), (4) POST `/result` → **C2-SIM ghi `ART-07-01` receipt**.
- **Surrogate:** thay injection-svchost bằng load+register; **giữ:** rundll32→DLL→callback→session register; **không giữ:** injection vào svchost/system.
- **Analysis/replay-only:** injection lịch sử (143→svchost, D8B3→Winlogon) — **không thực thi**; nghiên cứu telemetry injection ở S9b.
- **Telemetry:** E1 (rundll32 con của wmiprvse), E7 (DLL hash), E11 (token file — phụ), E3 (callback → 192.168.50.1:8080; attribution caveat), **`ART-07-01` server-side + server log**.
- **Fidelity:** mechanism `HIGH`; inject target `PARTIAL` (không tái hiện).
- **Acceptance (F10):** **server-side receipt `ART-07-01` + callback telemetry từ FS01 + evidence S8** cùng run ID. **Marker hoặc DLL tồn tại KHÔNG đủ.**

### S9b — Injection study (ANALYSIS-ONLY, không triển khai injection)
- **Historical:** D8B3→Winlogon (S2/S1 T1055.001); 143.dll→svchost (S2) — **hai claim riêng, mức evidence khác nhau** (xem mục 5).
- **Live lab behavior:** **không có** — không inject vào Winlogon/svchost/LSASS/system; **không cung cấp code/hướng dẫn triển khai injection** trong dự án.
- **Analysis/replay-only:** (a) phân tích tài liệu/mẫu telemetry historical (E10/E8 semantics), (b) nếu cần đo telemetry injection, chỉ **toy-process test do lab sở hữu** (`lab-target.exe`, đã xuất hiện trong sysmon working-tree E10 scope như telemetry target) với loader **được duyệt riêng từng lần** — chưa thiết kế code ở đây — hoặc (c) **telemetry replay** (tái phát event mẫu vào Elastic) để nghiên cứu rule.
- **Fidelity:** `PARTIAL`–`LOW` (không tái hiện đầy đủ injection C0015; **không gọi là "tái hiện injection"**).
- **Acceptance:** tài liệu phân tích + (nếu chọn toy/replay) test rule E10/E8 trên toy — không đụng process hệ thống.

### S10 — Collection & staging
- **Historical:** collection từ network shares; re-run ShareFinder; exfil **từ server khác backup server** (S2) `[OBSERVED-C0015]` (T1039/T1005/T1074.001).
- **Live lab:** từ session 2 (FS01), đọc corpus đã định (`\\FS01\Finance`: budget-q3.txt, payroll-notes.txt, server-inventory.txt) + ghi `ART-08-01` staging manifest (file/SHA-256/size) + staged copies.
- **Surrogate (F5):** FS01 gộp vai trò backup-server **và** file-server `[LAB-SURROGATE]` (đã ghi handoff §5 "FS01 consolidates…"); **fidelity `PARTIAL`** so với "exfil từ server khác"; phương án host riêng (thêm VM share-only) là tùy chọn tương lai, chưa thiết kế chi tiết.
- **Telemetry:** S5145 (FS01), E11 staging, E1 collector, E3 (nếu capture).
- **Fidelity:** `PARTIAL` (role consolidation); SMB-read mechanism `HIGH`.
- **Acceptance:** manifest ↔ corpus khớp (count, bytes, hash) + run ID.
- **Gap:** run collection cũ `[NOT-VERIFIED-IN-REPO]`; telemetry VM-side chưa có.

### S11a / S11b — Transfer → internal sink (hai lượt, mirror timeline)
- **Historical (F6):** Rclone → MEGA **lượt 1 (ngày 1)** và **lượt 2 (ngày 4)**, **RDP (ngày 2) xen giữa** `[OBSERVED-C0015]` (S2; T1567.002/T1030).
- **Live lab:** mỗi lượt = POST `/ingest/c0015-p5` → sink `p5_sink.py` (192.168.50.1:8081, allowlist SHA-256, ≤1024 B) với artifact đã duyệt từ `ART-08-01`; sink ghi `ART-09-01` receipt. Lab **nén timeline** (2 lượt cách nhau 1 RDP S12), ghi rõ deviation so với 4 ngày.
- **Surrogate:** MEGA → internal sink; bwlimit/multi-thread không tái lập (T1030 `PARTIAL`, ghi rõ).
- **Telemetry:** E3 (FS01 → 192.168.50.1:8081; attribution caveat), sink server log (client IP, bytes, hash), receipt; **cần bổ sung telemetry phía gửi (process/host/account)** — hiện mới có sink-side verified (M-33).
- **Fidelity:** `PARTIAL` (cloud/bwlimit).
- **Acceptance (F10):** receipt.hash == manifest.hash == allowlist; 2 receipt (2 lượt) + run ID; **không suy ra toàn chain từ sink artifact**.
- **Gap:** telemetry phía gửi chưa thiết kế event cụ thể — bổ sung khi chạy (E1 sender + E3).

### S12 — RDP interactive
- **Historical:** RDP tới backup server (ngày 2) qua beacon; backup console; taskmanager GUI; cũng ~9h sau 143.dll `[OBSERVED-C0015]` (S2; T1021.001).
- **Live lab:** RDP thật WS01↔FS01 (hoặc Kali→FS01 tùy milestone); capture S4624 Type 10, S4778/4779; định nghĩa **DET-008** (hiện `[NOT-VERIFIED-IN-REPO]` — undefined).
- **Telemetry:** S4624 Type 10, 4778/4779, E1 trong session.
- **Fidelity:** `HIGH` (RDP native).
- **Acceptance:** DET-008 defined + run RDP evidence + run ID.
- **Gap:** timeline lab nén (RDP đặt giữa hai lượt transfer theo F6); DET-008 chưa tồn tại trong repo.

### S13 — AnyDesk-like + ProcessAccess precursor
- **Historical:** AnyDesk `c:\users\<R>\Videos` (T1219.002) `[OBSERVED-C0015]`; ProcessHacker `C:\` root + "likely" LSASS access `[INFERRED-C0015]` (S2).
- **Live lab:** (a) AnyDesk-like: cài app portable hợp pháp vào thư mục bất thường (nếu chọn) — `[SUPPLEMENTAL-LAB-TECHNIQUE]`; (b) ProcessAccess: **phân tích telemetry E10** (scope lab-owned toy, config working-tree) — **không dump LSASS, không credential**.
- **Surrogate:** thay credential-access bằng access-attempt telemetry benign/toy.
- **Telemetry:** E1/E11 (install path bất thường), E10 (toy target).
- **Fidelity:** `PARTIAL` (relay thật không dùng; LSASS attempt không tái hiện).
- **Acceptance:** note phân tích + không có dữ liệu nhạy cảm tạo ra/lưu; E10 scope được duyệt.
- **Gap:** config E10 chưa commit/deploy-verify (giữ nguyên working-tree).

### S14 — Bounded impact + post-impact validation
- **Historical:** Conti batch → domain-joined systems (T1486); post-impact file listing (T1083); **không chạm DC** `[OBSERVED-C0015]` (S1/S2).
- **Live lab:** impact simulator **bounded**: chỉ lên corpus allowlist riêng (root cố định, caps file/bytes/time, không system path/UNC, không symlink escape, không SYSTEM, không tự lan) → note + rename/bounded replace; **restore** từ backup lab + verify count/hash/ACL.
- **Surrogate:** thay encryption bằng file transformation bounded (không general-purpose encryptor, không propagation).
- **Telemetry:** E2/E11/E26 high-rate (cần config+verify), S5145 (nếu SMB impacto), restore diff.
- **Fidelity:** invariants `HIGH`; encryption signature `PARTIAL` (không entropy thật).
- **Acceptance:** không exit corpus; restore verified; metrics (files/bytes/time) ghi.
- **Gap:** chưa có manifest/simulator; cần duyệt thiết kế riêng trước khi chạy.

### S15 — E2E: engineering + investigation
- **Historical:** toàn campaign là nguồn để E2E (design, plan.md:899–941).
- **Live lab:** run engineering (runbook visible) + run investigation (analyst chỉ nhận telemetry; ground truth = run ledger ẩn đến cuối); cùng run ID xuyên S1–S14; scorecard `ART-15-01`.
- **Fidelity:** — (phương pháp).
- **Acceptance:** analyst dựng lại chain từ telemetry, so sánh ledger; mọi phase có handoff + run ID.
- **Gap:** chỉ sau khi M-3..M-8 đạt (mục 8).

## 4.2 Làm rõ WMI telemetry (sửa lỗi F2)

- **Tạo process từ xa qua WMI (T1047)** sinh: nguồn S4648 (explicit credential) + kết nối DCOM/RPC (E3 — network connection, attribution caveat); đích S4624 Type 3, S4672, E1 `wmiprvse.exe → <child>`, S4688 (nếu audit). 
- **E19–21 (WMI-Activity)** là **filter/consumer/binding** — telemetry của **WMI subscription persistence (T1546.003)**; C0015 **không** ghi nhận WMI subscription. Không dùng E19–21 làm bằng chứng remote process creation; nếu chúng xuất hiện trong môi trường (audit chung), ghi rõ là hoạt động nền không thuộc chain.

## 5. Kỹ thuật A — DLL load vs DLL injection (triển khai được, không gộp)

### 5.1 `rundll32` nạp DLL (proxy execution, T1218.011)
- **Cơ chế:** DLL được map vào address space của `rundll32`; export được gọi (vd `DllRegisterServer`, custom export theo first-token sau dấu phẩy). **Không có process khác tham gia.**
- **Lab thiết kế (an toàn):** `rundll32.exe C:\C0015\c0015_143_surrogate.dll,<export-defined-in-dll>`; DLL thực hiện bước callback/register như S9 (không injection).
- **Evidence cần (và giới hạn từng loại):**
  | Claim cần chứng minh | Evidence | Giới hạn |
  |---|---|---|
  | rundll32 được tạo remote (S8) | FS01 E1 `wmiprvse→rundll32` + S4624/4672 + S4648 (WS01) | E1 parent phụ thuộc provider (Win32_Process Create → parent wmiprvse thường); không khẳng định mọi build |
  | rundll32 command line đúng | E1 `process.command_line` chứa DLL path + export | Command line có thể bị thiếu trên vài config (Sysmon CaptureCommandLine) |
  | DLL thực sự được nạp bởi rundll32 | **E7 ImageLoad** với ProcessGuid == E1 rundll32 + path/hash | E7 cần config bật (working-tree có include lab paths); ProcessGuid rỗng → hạ mức |
  | DLL tạo callback | **server-side registration receipt `ART-07-01`** + E3/E22 nếu capture (attribution caveat) | E3 có thể rỗng ProcessGuid/Image (P1-B) — receipt là bằng chứng độc lập |
  | Marker | E11 (token/result file) | **CHỈ là phụ** — không đơn độc (F10) |

### 5.2 DLL injection (T1055.001) — historical claims riêng
| Claim | Nguồn | Mức evidence | Trạng thái lab |
|---|---|---|---|
| D574.dll loaded via RunDll32 (không injection quan sát được; DNS-only, không kết nối) | S2 | `[OBSERVED-C0015]` (load); absense of connectivity `[OBSERVED-C0015]` | Không tái hiện => analysis-only |
| D8B3.dll → **Winlogon** injection (high integrity) | S2 (screenshots) + S1 T1055.001 | `[OBSERVED-C0015]` | **ANALYSIS-ONLY**; toy/replay nếu đo E10/E8 |
| 143.dll → **svchost** ('svchost.exe -k UnistackSvcGroup -s CDPUserSvc') injection | S2 | `[OBSERVED-C0015]` (DFIR mô tả injection) | **ANALYSIS-ONLY**; lab chỉ load+register (S9) |

- **Telemetry khác nhau (không gộp):** load = E1 (rundll32) + E7 (trong rundll32) + E3; injection = **E10 ProcessAccess** (source→target) + **E8 CreateRemoteThread** (nếu dùng) + **E7 trong target process** + S4688 của target (nếu audit) + E25 (hollowing). **E7 của rundll32 không chứng minh injection.**
- **Ranh giới:** không inject Winlogon/svchost/LSASS/system; **không cung cấp code/hướng dẫn injection** trong dự án; nếu cần đo telemetry → toy `lab-target.exe` duyệt từng lần hoặc telemetry replay; đánh dấu `PARTIAL`/`ANALYSIS ONLY`.

## 6. Handoff & correlation (tóm tắt — chi tiết `docs/handoff-contracts.md`, `docs/correlation-architecture.md`)

| Handoff | Producer | Artifact | Consumer | Khóa nối | Mức hiện tại | Thiếu gì |
|---|---|---|---|---|---|---|
| S1→S2 | S1 | E1 chain bundle | S2 | ProcessGuid (WS01) | `VERIFIED IN REPO` (mechanics) | hop mshta, run ID |
| S2→S3 | S2 | Session-1 receipt (server) | S3 | host+token+time | receiver `ARTIFACT VERIFIED` | receiver WS01; run |
| S4/S5→S6 | Discovery | `ART-04-01`→`ART-04-02` | S6 | run_id+host | primitives `VERIFIED`; artifact `NOT RUN` | artifact chưa tồn tại |
| S6→S7 | Decision | `ART-04-02` (account) | S7 | run_id | `NOT RUN` | run |
| S7→S8 | Auth | `ART-05-01` (LogonId) — evidence | S8 (dùng credential) | LogonId+host | `NARRATIVE ONLY` | exports |
| S8→S9 | WMI | `ART-06-01` | S9 | LogonId+ProcessGuid (FS01) | `NARRATIVE ONLY` | run mới |
| S9→S10 | 143.dll | `ART-07-01` receipt (server) | S10 | host+run_id+token | `NOT VERIFIED` | session chưa tồn tại |
| S10→S11 | Collection | `ART-08-01` manifest | S11 | hash+run_id | sink `ARTIFACT VERIFIED`; VM `NOT VERIFIED` | telemetry phía gửi |
| S11→S12+ | Sink | `ART-09-01` receipt | S12 | hash+run_id | `ARTIFACT VERIFIED` (1 file) | run record |

Correlation: C1 `DETECTED` (aggregation-level); C2/C3/C-SESSION2/C4 `UNPROVEN` (chờ run mới). Tier: `DIRECT EVENT
LINK` / `SUPPORTED HANDOFF` / `CONTEXTUAL ONLY` / `UNPROVEN` / `CONTRADICTED`; hạ mức khi ProcessGuid/LogonId rỗng,
PID mâu thuẫn, clock skew, E3 không attribution. **Run ID là ground-truth metadata — endpoint event không tự mang
run ID; gắn qua orchestration/artifact + đối chiếu ledger.**

## 7. Phân loại triển khai

- **Surrogate-deployable (an toàn khi user duyệt):** S1–S8, S10–S12, S15.
- **Analysis/replay-only (kiểm soát phiên riêng):** S9b (injection — toy/replay), S13b (ProcessAccess — không dump),
  S14 (impact — simulator bounded, duyệt riêng), S3b (D574 DNS-only case).
- **Chưa đủ evidence (giữ nguyên):** claims post-09-19 (3B/4/5/6, DET-008, T1018/1016) `[NOT-VERIFIED-IN-REPO]`;
  Phase 1 PID/entity conflict `UNRESOLVED`.

## 8. Thứ tự triển khai (milestone + acceptance — chi tiết `docs/implementation-plan.md`)

| Milestone | Scope | Acceptance (tóm tắt) |
|---|---|---|
| M-0 | Chốt plan v2 (tài liệu này) + labels | Mọi docs dùng 5-lớp; changelog F1–F10 áp dụng |
| M-1 | P0 evidence correctness | Conflicts ghi đúng; không nâng claim |
| M-2 | Sensor/clock/field mapping (LogonId, ProcessGuid, E7 path, E3 attribution) | Clock sync; field verified trên sample |
| M-3 | S1–S3 | E1 chain + session-1 receipt + run ID |
| M-4 | S4–S8 | `ART-04-01/02`→`ART-06-01` + 4 completion-gate |
| M-5 | S9 (+S9b analysis) | `ART-07-01` server-side + callback telemetry |
| M-6 | S10–S11a/b | manifest↔receipt↔allowlist hash khớp (2 lượt) |
| M-7 | S12–S13 | DET-008 defined; no dump |
| M-8 | S14 | restore verified; không exit corpus |
| M-9 | S15 E2E | scorecard; ground truth ẩn |

## 9. Ranh giới (không vượt)

Không malware thật, không Cobalt Strike/Bazar binary, không C2 framework công khai; không credential acquisition/
dump; không arbitrary shell/payload runner; không injection vào LSASS/Winlogon/svchost/system; không cung cấp
code/hướng dẫn injection; không public cloud/MEGA/Telegram; không general-purpose encryptor/propagation; không ghi
secret vào repo. Impact surrogate: allowlist root + caps + restore. Detection không phụ thuộc tên file/IP cố định.

---

# Canonical phase map (0–15) & OLD→NEW — hấp thụ từ `docs/phase-map.md` (đã gộp)

## 10. Canonical phase map

Evidence status vocabulary (nhất quán toàn repo): `VERIFIED IN REPO`, `ARTIFACT VERIFIED`, `NARRATIVE ONLY`,
`NOT VERIFIED`, `NOT RUN`, `PARTIAL`, `SENSOR GAP`, `INGEST/MAPPING GAP`, `DETECTION MISS`, `DETECTED`, `CONTRADICTED`.
Claim labels: `[OBSERVED-C0015]`/`[OBSERVED]`, `[INFERRED-C0015]`/`[INFERRED]`, `[UNKNOWN-C0015]`/`[UNKNOWN]`,
`[LAB-SURROGATE]`/`[LAB ASSUMPTION]`, `[SUPPLEMENTAL-LAB-TECHNIQUE]`, `[NOT-VERIFIED-IN-REPO]`.

Số hiệu canonical (0–15) **supersede** hệ 0–11 cũ (`docs/plan.md`, lưu lịch sử); hai hệ cùng tên khác nghĩa đã từng
gây mâu thuẫn status (audit 2026-09) — bảng OLD→NEW ở mục 11 cố định cách đối chiếu. Mọi "recorded PASS" post-09-19
(auth bridge, DLL branch, WMI canary, collection run, DET-008) giữ `NARRATIVE ONLY`/`NOT VERIFIED` tới khi có raw
evidence — không viết lại thành PASS.

| Phase | Tên chuẩn (canonical) | Trạng thái evidence | Input → Output / handoff | Host / account | ATT&CK anchors | Gap |
|---|---|---|---|---|---|---|
| 0 | Baseline & sensor readiness | `PARTIAL` — ingest validated (lab-journal 09-12/14); 4 deliverable còn thiếu | — → sensor matrix | toàn lab | — | IP VM chưa re-verify; clock skew Kali |
| 1 | Entry: Word macro → HTA | `VERIFIED IN REPO` (P1-A/B/C); delivery `NOT REPRODUCED` (trigger thủ công) | P0 → chain artifacts | WS01 `duc.user` | T1204.002, T1566.001 (assessed), T1059.005/.007, T1218.005, T1027 | entity/PID conflict `UNRESOLVED`; hop mshta chưa nối |
| 2 | Bootstrap → loader → session 1 (Bazar-like) | `PARTIAL` — public-IP mock verified artifact; receiver session-1 đã implement (`scripts/c2sim_v2.py`), chưa chạy lab | P1 → session-1 token | WS01 | T1016, T1105, T1218.010/.011 | JA3/cert không tái lập; chưa run ID |
| 3 | Session 1 + operator discovery | `NOT RUN` — CALDERA v5 quyết định (`docs/payloads-and-c2.md`), chưa deploy | P2 → found_shares → P4 | WS01 session 1 | T1059.003, T1057, T1018, T1069, T1482, T1135, T1124 | Không session record |
| 4 | Discovery → decision → target | `PARTIAL` — T1057/T1069.002/T1482/T1135/T1039 `DETECTED` (09-15); artifact chưa tồn tại; T1018/T1016 `CONTRADICTED` | P3 → `ART-04-01/02` → P5/P6 | WS01 `duc.user` | T1135, T1074.001, T1018, T1016 | Chưa run ID |
| 5 | Auth bridge (identity pre-provisioned) | `NARRATIVE ONLY` (4648/4624/4672 claims) | P4 → `ART-05-01` evidence → P6 | WS01→FS01 `it.admin` (không DA) | valid accounts (lab), auth study | Toàn bộ narrative-only |
| 6 | WMI lateral movement (T1047) | `NARRATIVE ONLY` (canary claim) | P5 + P4 → remote-process evidence → P7 | WS01→FS01 `it.admin` | T1047, T1570 | Không bằng chứng truy cập được |
| 7 | `143.dll` surrogate → second session | `NOT VERIFIED` — mục tiêu cần chứng minh; receiver `ARTIFACT VERIFIED` | P6 → **`ART-07-01` receipt** → P8 | FS01 `it.admin` (WMI ctx) | T1218.011, T1105, T1570; injection KHÔNG tái lập | Marker không đủ; không run ID |
| 8 | Collection & staging | `PARTIAL` — S5145 read verified (EXP-005); sink-side verified; VM-side chưa | P7 → `ART-08-01` → P9 | FS01 session 2; shares Finance/IT | T1039, T1005, T1074.001 | Loopback S5145 chưa verify |
| 9 | Transfer → internal sink | `NOT RUN` — sink allowlist verified artifact | P8 → `ART-09-01` receipt → P10/P15 | FS01 → host sink | T1567.002 surrogate, T1030 xấp xỉ | Sender telemetry thiếu |
| 10 | RDP interactive | `NOT VERIFIED` — DET-008 undefined | P9 → RDP bundle → P11 | WS01↔FS01 `it.admin` | T1021.001 | Không evidence |
| 11 | AnyDesk-like + LSASS-access telemetry study | `NOT RUN` — thiết kế an toàn (E10 quyền tối thiểu, KHÔNG dump) | P10 → notes → P12 | FS01 | T1219.002; T1003.001-adjacent (supplemental) | Relay public không dùng |
| 12 | Impact preparation (manifest) | `NOT RUN` | P11 → impact manifest → P13 | FS01 | T1486 prep | Chưa có manifest |
| 13 | Bounded impact surrogate | `NOT RUN` — payload `payloads/impact/c0015_impact.ps1` đã test offline | P12 → metrics → P14 | FS01 corpus allowlist | T1486 surrogate, T1083 | Entropy signature không tái lập |
| 14 | Post-impact validation & recovery | `NOT RUN` — Rollback/Verify đã test offline | P13 → recovery report → P15 | FS01 | recovery | Snapshot ≠ enterprise recovery |
| 15 | E2E engineering + investigation | `NOT RUN` | toàn bộ → scorecard `ART-15-01` | toàn lab | toàn campaign | Ground truth ẩn trong investigation run |

## 11. OLD → NEW mapping (0–11 → 0–15)

Old numbering = `docs/plan.md` (lưu lịch sử). Notable collisions đánh dấu — trích claim cũ phải nêu hệ số.

| OLD (0–11) | NEW (0–15) | Notes |
|---|---|---|
| 0 Ground truth/sensors | 0 | Cùng nghĩa; deliverables còn thiếu |
| 1 Initial access/bootstrap (verified) | 1 + 2 | **Collision:** OLD "Phase 1 = bootstrap PASS" vs NEW "Phase 1 = entry point" |
| 2 Bazar stage | 2 (+3) | Bazar surrogate ≈ NEW 2 |
| 3 Cobalt Strike stage (CALDERA) | 3 (+4) | **Collision:** discovery chuyển sang NEW 4 |
| 4 Discovery & target selection | 4 | NEW 4 thêm artifact discovery→target bắt buộc |
| 5 Privileged-access prerequisite | 5 | Handoff "3B" = auth bridge run (narrative) |
| 6 WMI lateral movement | 6 | "Phase 4 DLL branch" (handoff) thuộc NEW 6/7 — không trộn |
| 7 DLL injection reconstruction | 7 (subset) | **Collision:** OLD 7 = injection experiment; NEW 7 = second session handoff |
| 8 Collection and transfer | 8 + 9 | NEW tách staging (8) và sink (9) |
| 9 RDP + secondary access | 10 + 11 | RDP→10; AnyDesk/credential precursor→11 |
| 10 Conti impact | 12 + 13 + 14 | Prep/bounded/validation tách 3 |
| 11 Prevention/containment/recovery | 14 + 15 | E2E→15 |

## 12. Naming & ID conventions

- **run ID:** `RUN-YYYYMMDD-<seq>` — không gộp event khác run thành một chuỗi.
- **scenario ID:** `C0015-LAB-<n>`. **artifact ID:** `ART-<phase>-<nn>` (schema: `docs/handoff-contracts.md`).
- **Phase 1 PID conflict:** entity_id suffix `…001500` = PID 5376 ≠ ghi 3604/5872 — `UNRESOLVED`, không tự chọn PID.

## 13. Known contradictions (giữ nguyên)

| Contradiction | Chi tiết | Trạng thái |
|---|---|---|
| T1018/T1016 | Repo (lịch sử `fe41049`) NOT RUN vs handoff "PASS" | `CONTRADICTED` |
| DET-008 (RDP) | Chỉ trong handoff; repo không định nghĩa | `NARRATIVE ONLY` |
| Phase 1 PID/entity | suffix `…001500` (5376) vs 3604/5872 | `CONTRADICTED` — UNRESOLVED |
| PID 6100 vs 5752 | Hai run DLL branch/WMI canary (handoff) | `NARRATIVE ONLY` — không hợp nhất |
| Sysmon baseline | Live (handoff 2026-09-26): 7/10 disabled, hash `D30CD93C…` ≠ committed ≠ working-tree | Bản thứ ba chưa vào repo — M-1 reconcile |
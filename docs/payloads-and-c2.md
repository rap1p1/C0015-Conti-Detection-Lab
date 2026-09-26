# Payloads & C2 Decisions (2026-10) — phê duyệt 3 giai đoạn theo campaign

> Trả lời yêu cầu: (1) đối chiếu 3 giai đoạn với campaign gốc, (2) quyết định C2 (foothold + operator) dựa trên
> nghiên cứu cài đặt thực tế, (3) đánh giá mô hình AD 3 máy. Chain blueprint chính vẫn là
> `docs/implementation-plan.md` (v3.2); file này chốt payload + hạ tầng C2.

## 1. Đối chiếu 3 giai đoạn của bạn với campaign gốc

| Giai đoạn bạn yêu cầu | C0015 gốc (DFIR/MITRE) | Kết luận đối chiếu |
|---|---|---|
| 1. PAYLOAD + macro trong docm → macro→HTA→benign bootstrap → dừng ở callback beacon | Word macro (T1204.002) → HTA JS/VBS encoded (T1059.005/.007, T1027) → tải `compareForfor.jpg` (T1036, T1105) → REGSVR32 (T1218.010) → Bazar callback + myexternalip (T1016) | **KHỚP — 1:1**. Lab: cùng chuỗi, DLL benign đuôi `.jpg`, callback vào C2-SIM v2 (không Bazar/CS thật). Fidelity HIGH cho chain mechanics; delivery email `[INFERRED-C0015]` → lab thay bằng bước tạo ZIP có password + docm đặt vào WS01 (thực thi được, xem §4) |
| 2. BẠN đóng operator: discovery → chọn đích → auth lab → WMI + process/DLL benign → collection → transfer dữ liệu giả tới sink nội bộ; RDP tiếp theo; AnyDesk + truy cập LSASS PHẢI được nghiên cứu | Operator từ runbook (copy-paste errors — S2) → ShareFinder/found_shares → WMIC→rundll32→143.dll (T1047/T1570) → Rclone/MEGA ×2 (T1567.002/T1030) → RDP ngày 2 (T1021.001) → AnyDesk `Videos\` (T1219.002) → Process Hacker → LSASS "likely" (T1003.001-adjacent, ngày 5) | **KHỚP, đúng thứ tự nguồn** (2 lượt transfer, RDP xen giữa). Khác biệt an toàn: MEGA→sink nội bộ; WMI dùng `it.admin` pre-provisioned + credential tường minh (runas/CIM `-Credential` — đã sửa §2.2); **LSASS = nghiên cứu telemetry an toàn** (E10 access-mask, KHÔNG dump — §3.2) |
| 3. PAYLOAD KHÁC giới hạn trên corpus dummy riêng + kiểm tra phạm vi + khôi phục (vẫn đủ telemetry Conti) | Conti batch deploy domain-wide (T1486) + post-impact file listing (T1083); không chạm DC | **KHỚP về telemetry, khác về phạm vi (bắt buộc an toàn)**: `c0015_impact.ps1` giữ các observable của Conti (fan-out tốc độ cao, rename/extension, note creation, breadth) trên corpus allowlist + restore verify; không encrypt thật, không lan truyền, không chạm DC (campaign cũng không chạm DC — fidelity +1) |

**Chính sách "không technique nào UNKNOWN/OBSERVED-ONLY":** mọi bước của chain đều có hành vi thực thi được trong
lab. Các khoảng trống lịch sử được **thay bằng technique thực thi kèm label** (không để trống, không đánh dấu
unknown trong chain):
- Delivery phishing (`[INFERRED-C0015]`) → **thực thi**: tạo ZIP password + docm thật, đặt vào WS01, mở bằng mật khẩu (chỉ phần email-transport là surrogate — bước tạo/mở artifact là thật).
- Credential provenance (`[UNKNOWN-C0015]` lịch sử) → **thực thi**: S7 auth controls (denied/allowed/revoked) chứng minh authorization; operator sở hữu credential pre-provisioned là input thật của run (`[LAB-SURROGATE]`).
- LSASS access (`[INFERRED-C0015]`) → **thực thi an toàn**: Process-Hacker-like tool của lab mở handle tới lsass.exe với quyền tối thiểu (`PROCESS_QUERY_LIMITED_INFORMATION`) → E10 ProcessAccess thật với target `lsass.exe` + phân tích access mask; KHÔNG đọc memory, KHÔNG dump, KHÔNG credential (§3.2).
- Transfer mechanism 143.dll lên target (`[UNKNOWN-C0015]`) → **thực thi**: S8a copy qua admin share C$ (T1570 surrogate) với evidence riêng.
- Injection D8B3/143 (`[OBSERVED-C0015]`) → **thực thi dạng replay/toy**: fixture E10/E8 + toy `lab-target.exe` nếu duyệt — không inject process hệ thống (ranh giới cứng, không đổi).

## 2. Quyết định C2 — foothold vs operator channel (nghiên cứu đã xác minh cài đặt)

### 2.1 Foothold tự động (S1→S3): C2-SIM v2 (đã implement + test 15/15)
Giữ `scripts/c2sim_v2.py`: register/task/result với **task allowlist cố định**, receipt server-side. Lý do: chuỗi
macro→HTA→DLL→beacon cần telemetry **xác định** (parent chain, E7 hash, callback) để map 1:1 với campaign; một C2
framework thật sẽ thay đổi toàn bộ signature quá trình (không còn regsvr32/rundll32 chain của Bazar).

### 2.2 Operator C2 hậu xâm nhập: CALDERA (primary) — Sliver (tùy chọn có điều kiện) — Havoc (không dùng mặc định)

| Tiêu chí | **Apache CALDERA v5** (khuyến nghị primary) | **Sliver** (tùy chọn) | **Havoc** (loại mặc định) |
|---|---|---|---|
| Cài đặt (đã đối chiếu README chính chủ) | `git clone https://github.com/apache/caldera.git --recursive` → `pip3 install -r requirements.txt` → `python3 server.py --insecure --build`; yêu cầu Linux/macOS + Python 3.10+, 8GB RAM khuyến nghị; UI `http://localhost:8888` (red/admin); **v5.1.0+ bắt buộc** (CVE-2025-27364) | `curl https://sliver.sh/install | sudo bash`; server/client trên Kali; implant Windows qua profile (HTTP(S)/mTLS/DNS), compile động | Teamserver Go chạy Kali/Ubuntu; client cần build Qt + Python 3.10 (nặng hơn) |
| Vai trò trong lab | Operator layer: sandcat agent trên WS01/FS01, adversary profile YAML = runbook C0015 (đúng lệnh DFIR), operation replay, task/result log = ledger bổ trợ | Kênh tương tác operator thay vai CS beacon (interactive tasking) | — |
| Điểm phải kiểm soát | Server chỉ bind mạng lab (KHÔNG ra public — khuyến cáo chính chủ của MITRE); RAM: cài trên **ELASTIC01 (Ubuntu 24.04, Azure)** thay vì Kali nếu VM Kali quá hẹp | **Chỉ dùng transport/tasking**: KHÔNG dùng tính năng process migration/injection/token (ranh giới dự án); implant = agent thật → cần **exclusion Defender trong lab** (cấu hình lab, không phải bypass-engineering); telemetry khác CS (JA3) → fidelity PARTIAL ghi rõ | **Demon agent có sẵn evasion**: Ekko sleep obfuscation, indirect syscalls, AMSI/ETW patching qua HW breakpoints — vi phạm ranh giới "no EDR/AV bypass". Không dùng trừ khi user yêu cầu lại với custom agent benign riêng |
| Kết luận | **USE — primary operator C2** | **USE (optional, có điều kiện trên)** | **NOT USED (mặc định)** |

**Bản đồ vai trò C2 trong chain:** C2-SIM v2 = beacon channel của Bazar/143.dll surrogate (S3/S9, signature sát
campaign); CALDERA = operator orchestration/tasking (S4–S13, mirror "operator từ runbook"); Sliver (nếu chọn) =
kênh interactive thay vai CS operator session — ba lớp không thay thế nhau, ghi rõ fidelity từng lớp.
**Điều kiện cứng khi dùng Sliver/CALDERA:** chỉ trong VMnet2, chỉ tới WS01/FS01 do bạn sở hữu, không expose public,
không dùng tính năng injection/evasion/credential của chúng, mọi task vẫn theo allowlist runbook.

## 3. AnyDesk + LSASS trong lab (bắt buộc nghiên cứu, thực thi an toàn)

- **AnyDesk (T1219.002):** cài **AnyDesk portable chính hãng** vào thư mục bất thường (`C:\Users\Public\Videos\` —
  mirror DFIR) trên FS01; chạy để thu: E1/E11 (install path lạ), E3/E22 tới dải IP hợp lệ của AnyDesk (đúng
  observable DFIR mô tả: "long connection towards legitimately registered IPv4 ranges"), service/registry nếu cài.
  Session điều khiển (nếu cần) chỉ nội bộ lab; không dùng relay công khai làm kênh C2.
- **LSASS access (T1003.001-adjacent, `[SUPPLEMENTAL-LAB-TECHNIQUE]`):** lab tự viết tool benign (C#/C nhỏ) mở
  handle tới `lsass.exe` với **PROCESS_QUERY_LIMITED_INFORMATION** (quyền tối thiểu, không đọc memory) → sinh
  **E10 ProcessAccess thật** với target `lsass.exe` + access mask để detection phân biệt quyền thấp (benign/control)
  vs quyền cao (PROCESS_VM_READ/PROCESS_ALL_ACCESS = mẫu tấn công — chỉ xuất hiện trong **fixtures replay**, không
  thực thi). **KHÔNG dump, KHÔNG đọc credential, KHÔNG dùng kết quả cho WMI.** Detection `C-LSASS` + fixtures đã có
  (`scripts/fixtures/e10_lsass_probe.json`).

## 4. Mô hình AD lab — 3 máy có đủ không?

Đối chiếu mô hình phổ biến: **GOAD** (full: 5 VM/2 forest/3 domain; **GOAD-Light: 3 VM/2 domain**; MINILAB: 2 VM),
**DetectionLab** (DC+WEF+Win10, đã archive 2021), **BadBlood** (bơm hàng nghìn user/group/computer/OUs vào domain có
sẵn — chỉ cần Domain Admin + AD PowerShell, mỗi lần chạy sinh kết quả khác nhau).

**Kết luận:** DC01 + WS01 + FS01 (+ Kali + ELASTIC01 remote) **đủ cho campaign này** — ngang scale GOAD-Light, và
khớp chính xác cấu trúc campaign (1 workstation beachhead + 1 file/backup server + DC **không bị chạm** — đúng DFIR).
Điểm yếu hiện tại là **AD quá trống** (2 user, 2 share): discovery trả về ít dữ liệu. Khuyến nghị (theo thứ tự):
1. **BadBlood trên DC01** — bơm ~2500 user/groups/computers/OUs dummy → `net group`, `net view /all /domain`,
   ShareFinder, found_shares có đầu ra thật và phong phú (đây là nâng cấp giá trị/chi phí tốt nhất, không cần VM mới).
2. **Thêm máy thứ 4 (DATA01/WS02) chỉ khi RAM cho phép** — host 16 GB đang chạy 4 VM; một Windows 2 GB nữa là ngưỡng.
   Nếu thêm: DATA01 (file server thứ hai) để khôi phục fidelity "exfil từ server khác backup server" (S10, §4 blueprint).
3. Không cần forest thứ hai/trust (T1482 nltest vẫn chạy được và trả về kết quả hợp lệ dù single-domain — ghi giới hạn).

## 5. Thứ tự bổ sung vào runbook M-1 (khi bạn duyệt chạy)

1. Env verify (như blueprint §5 M-1) + cài **CALDERA v5.1.0+ trên ELASTIC01** (hoặc Kali) theo §2.2, sandcat agent
   lên WS01/FS01, tạo adversary profile C0015 = đúng các lệnh DFIR của S4.
2. Deploy payloads: build DLL (mingw) → config.ini mỗi run → docm macro → chạy S1–S3 với C2-SIM v2 + beacon.
3. BadBlood trên DC01 (nếu bạn muốn discovery giàu dữ liệu).
4. (Tùy chọn) Sliver theo điều kiện §2.2 — chỉ sau khi CALDERA chạy ổn.

## 6. C2-SIM v2 — endpoint design (hấp thụ từ `docs/c2-sim-design.md` cũ)

Server HTTP constrained, chạy trên host lab/Kali, đóng vai C2 cho surrogate beacon; code: `scripts/c2sim_v2.py`
(đã test 15/15 offline + test end-to-end với `payloads/beacon/c0015_beacon.ps1`).

| Endpoint | Method | Mục đích | Điều kiện (allowlist) |
|---|---|---|---|
| `/dl/<name>` | GET | Phân phối DLL surrogate (T1105 ingress analog) | name ∈ DL allowlist; file staged trong `--dl-dir` |
| `/session/register?stage=&host=&token=&run=` | POST | Đăng ký session (beacon check-in) | stage ∈ `{phase3, phase7-session2, phase4-rundll32}`; host ∈ map stage; token `S[12]-<16 hex>` |
| `/task/next?session=` | GET | Trả task cố định tiếp theo | session đã register |
| `/result?session=&task=` | POST | Nhận result benign (cap bytes) | task ∈ allowlist; size ≤ cap |
| `/checkin` (legacy) | GET | Callback 1-shot phase4 | `stage=phase4-rundll32&host=FS01` |

- **Task allowlist:** `T-DISCOVER-CORPUS`, `T-BEACON-SLEEP`, `T-NOOP` — **không task nào nhận command string**.
- **Session/token:** token do agent sinh (`S[12]-<16 hex>`), không phụ thuộc credential; server lưu
  `{token, stage, host, ip, time}` và khi register `phase7-session2` hợp lệ ghi **`ART-07-01` receipt** (schema
  `docs/handoff-contracts.md` §1) — bằng chứng server-side của session 2; marker endpoint chỉ là phụ.
- **KHÔNG tái lập (fidelity partial):** Malleable C2/JA3/cert profile, sleep 60s/jitter 37, injection vào
  svchost/Winlogon (ranh giới) — thay bằng bounded sleep có log; detection không dựa interval cố định.
- **Telemetry kỳ vọng:** E1 rundll32 (parent wmiprvse), E7 ImageLoad (hash, unsigned), E11, E3 callback
  (ProcessGuid caveat — P1-B lesson), server log + receipt.

# C0015 Phase Handoff & Artifact Contracts (v2)

> Thiết kế chuỗi: mỗi phase nhận **input có bằng chứng từ phase trước**, tạo **output artifact có định dạng +
> provenance** rõ, và phase sau **tiêu thụ output đó** — không hard-code target. Đây là tài liệu thiết kế/contract;
> không phải record rằng các phase đã chạy. Trạng thái evidence theo `docs/evidence-matrix-v2.md`.
>
> Nguyên tắc: chỉ gọi một handoff là `SUPPORTED` khi có bằng chứng producer/consumer (artifact được tạo bởi phase
> A và được đọc bởi phase B, kèm run ID). Trùng timestamp/tên marker **không** đủ.

## 0. Chuỗi handoff tổng quan (producer → artifact/state → consumer)

| # | Producer phase | Artifact / state | Consumer phase | Bằng chứng yêu cầu |
|---|---|---|---|---|
| H0 | P0 baseline | Sensor matrix + run ledger schema | P1..P15 | `docs/evidence-matrix-v2.md` M-01..04; ledger file `evidence/run-ledger/RUN-<id>.json` (schema §9) |
| H1 | P1 entry → P2 bootstrap | Chain telemetry bundle (E1 chain + E7/11) — **không phải artifact file** | P2/P3 session | E1 parent-child + E7 hash liên tục (P1-C verified; hop mshta `[UNKNOWN]` — xem M-15) |
| H2 | P3/P4 discovery | `ART-04-01` discovery result → `found_shares`-like artifact (`C:\ProgramData\found_shares.txt` — mirror DFIR path, `[LAB ASSUMPTION]` format) | P4 decision / orchestration | M-20..22 verified primitives; artifact chưa tồn tại — `NOT RUN` |
| H3 | P4 decision | `ART-04-02` `target-manifest.json` (target = FS01, justification, run_id, auth_account) | P5/P6 | Chưa tồn tại — bắt buộc tạo trong lần chạy P4 |
| H4 | P5 auth bridge | `ART-05-01` auth evidence bundle (S4648/4624/4672 + LogonId) | P6 | M-40 narrative-only — cần exports |
| H5 | P6 WMI | `ART-06-01` remote-process evidence (FS01 S4624/4672 + E1 wmiprvse→child) | P7 | M-41 narrative-only |
| H6 | P7 143.dll surrogate | `ART-07-01` **session-2 registration receipt (server-side, C2-SIM)** + `ART-07-02` endpoint callback telemetry | P8 | M-42/43 chưa verify — đây là tiêu chí đóng P7 |
| H7 | P8 collection/staging | `ART-08-01` staging manifest (file, SHA-256, size, perms) | P9 | M-32/33 sink verified; VM-side `NOT VERIFIED` |
| H8 | P9 transfer | `ART-09-01` sink receipt (timestamp, client, bytes, hash) | P10/P15 | M-33 verified-1 file; run record thiếu |
| H9 | P10 RDP | `ART-10-01` RDP session bundle (S4624 Type 10, 4778/4779) | P11/P15 | M-44 narrative-only |
| H10 | P11 precursor | `ART-11-01` telemetry analysis note (AnyDesk-like, Process Access — **chỉ phân tích**) | P12 | Không chạy |
| H11 | P12 impact prep | `ART-12-01` impact manifest (allowlist root, caps) | P13 | Không chạy |
| H12 | P13 impact | `ART-13-01` impact metrics + restored corpus verification | P14 | Không chạy |
| H13 | P14 validation | `ART-14-01` recovery report (count/hash/ACL) | P15 | Không chạy |
| H14 | P15 E2E | `ART-15-01` reconstruction scorecard (giấu ground truth trong investigation run) | — | Không chạy |

## 1. Artifact schemas (tối thiểu)

Tất cả artifact JSON: `{ "artifact_id", "run_id", "scenario_id", "created_utc", "producer_phase", "consumer_phase", "schema_version" }` + payload.

### `ART-04-01` discovery result (mirror `found_shares.txt`)
```json
{ "artifact_id": "ART-04-01", "run_id": "RUN-...", "created_utc": "...",
  "producer_phase": 3, "consumer_phase": 4,
  "shares": [ { "host": "FS01", "share": "Finance", "path": "\\\\FS01\\Finance",
                "readable": true, "sample_files": ["budget-q3.txt","payroll-notes.txt"] } ] }
```
- Historical mirror: DFIR ghi ShareFinder → `c:\ProgramData\found_shares.txt` (tạo bởi Rundll32.exe). Lab có thể ghi
  `C:\ProgramData\found_shares.txt` (text) + bản JSON đầy đủ — path mirror là `[LAB ASSUMPTION]`; detection không
  được phụ thuộc path này.

### `ART-04-02` target manifest
```json
{ "artifact_id": "ART-04-02", "run_id": "RUN-...", "producer_phase": 4, "consumer_phase": 6,
  "target": { "host": "FS01", "ip": "192.168.50.30", "share": "Finance",
              "selection_reason": "readable high-value share from ART-04-01" },
  "auth": { "account": "C0015\\it.admin", "provisioned": true, "provenance": "LAB ASSUMPTION" },
  "allowed_actions": ["wmi_remote_process", "dll_surrogate", "collect_finance_corpus"] }
```

### `ART-07-01` session-2 registration receipt (server-side C2-SIM — bắt buộc)
```json
{ "artifact_id": "ART-07-01", "run_id": "RUN-...", "server": "192.168.50.1:8080",
  "client_ip": "192.168.50.30", "host": "FS01", "stage": "phase7-session2",
  "session_token": "S2-<sha256-16hex>", "registered_utc": "...", "task_ids": ["T-DISCOVER-CORPUS"],
  "evidence_links": ["FS01 E1 rundll32 (parent wmiprvse)", "FS01 E7 ImageLoad", "FS01 E3 → 192.168.50.1:8080"] }
```

### `ART-08-01` staging manifest
```json
{ "artifact_id": "ART-08-01", "run_id": "RUN-...", "producer_phase": 8, "consumer_phase": 9,
  "files": [ { "path": "\\\\FS01\\Finance\\payroll-notes.txt", "size": 32,
               "sha256": "DEAD1ABD...", "read_utc": "..." } ], "total_bytes": 32 }
```

### `ART-09-01` sink receipt
```json
{ "artifact_id": "ART-09-01", "run_id": "RUN-...", "sink": "192.168.50.1:8081",
  "client_ip": "192.168.50.30", "bytes": 32, "sha256": "DEAD1ABD...", "accepted": true,
  "received_utc": "...", "output_path": "C:\\C0015\\P5\\sink\\received-payroll-notes.txt" }
```

## 2. Handoff contracts chi tiết (H2–H8 trọng yếu)

### H2/H3 — Discovery → artifact → decision → target selection
- **Precondition:** session 1 (P3) active trên WS01; P0 sensors OK; discovery primitives (P4) chạy được (một phần
  verified: M-20).
- **Input contract:** session token P2→P3; không hard-code target.
- **Action scope:** chạy bộ discovery theo đúng lệnh DFIR: `tasklist /s`, `net group "domain admins" /dom`,
  `net localgroup "administrator"`, `nltest /domain_trusts /all_trusts`, `net view /all /domain`,
  `net view /all time`, `ping <host>` (T1018/T1016 replay theo raw evidence khi có). ShareFinder surrogate: liệt kê
  shares bằng `net view`/`Get-SmbShare` (read-only), không PowerView payload thật nếu chưa cần.
- **Expected telemetry:** E1 cho từng lệnh (parent = session-1 agent/rundll32 analog); S5145 không bắt buộc ở bước này;
  `C:\ProgramData\found_shares.txt` (E11 nếu enable path) + `ART-04-01`.
- **Output contract:** `ART-04-01` (discovery) + `ART-04-02` (target manifest) — orchestration đọc `ART-04-01` và
  **ghi `ART-04-02` chọn FS01 kèm reason**.
- **Detection/correlation:** C1 (hiện hữu) + tương lai `C-DECISION` (discovery family → target manifest mới được tạo);
  join keys: run_id, host, user, E1 parent-chain (ProcessGuid).
- **Negative/control path:** discovery không tìm thấy share đọc được → `ART-04-02` không được tạo → P6 `NOT RUN`
  (không hard-code FS01); sensor mất E1 → dừng, sửa sensor (phase gate).
- **Acceptance:** `ART-04-02.target.host == FS01` **được suy ra từ `ART-04-01.shares`** (có dòng log
  orchestration ghi `selection_reason`); ít nhất 4 behavior family DETECTED + artifact tồn tại cùng run ID.
- **Evidence status:** primitives `VERIFIED IN REPO`; artifacts `NOT RUN`.

### H4/H5 — Target → auth context → WMI remote process
- **Precondition:** `ART-04-02` tồn tại; `it.admin` pre-provisioned (quyền đọc trên FS01, không DA — plan.md:398–402).
- **Input contract:** `ART-04-02` (target + auth account); credential từ operator (pre-provisioned, không dump) —
  đây là **input điều khiển thật**; bundle S4648/4624/4672 sinh ra là **EVIDENCE** (chứng minh credential đã được
  dùng), không phải dữ liệu để phase sau "thực thi".
- **Action scope:** WS01 chạy WMI remote process creation hướng FS01 với proxy `rundll32.exe` + benign DLL:
  `wmic /node:FS01 /user:C0015\it.admin process call create "rundll32.exe C:\C0015\c0015_143_surrogate.dll,<export>"`
  (export do DLL định nghĩa; mirror DFIR: WMIC remote process creation → rundll32 → 143.dll).
- **Expected telemetry:**
  - WS01: S4648 (explicit credential); E3 (network connection WS01→FS01 — **E3 là network connection, không chứng
    minh RPC**; attribution có thể rỗng — giữ mức `CONTEXTUAL ONLY` nếu thiếu ProcessGuid).
  - FS01: S4624 Type 3 + S4672 + S4688 (nếu audit) + **E1 `wmiprvse.exe → rundll32.exe` (bằng chứng then chốt)** +
    E7 ImageLoad DLL (unsigned, staging path) + E11 marker/token. **(E19–21 = WMI filter/consumer/binding, telemetry
    của WMI subscription T1546.003 — KHÔNG phải event của remote process creation; không kỳ vọng ở đây.)**
- **Output contract:** `ART-06-01` (remote-process evidence bundle, gồm LogonId từ S4624/4672).
- **Detection/correlation:** C3 (Identity/WMI pivot): join WS01 S4648 ↔ FS01 S4624/4672 qua LogonId (cùng LogonId
  xuất hiện ở event phía source và target khi dùng explicit credential — cần verify field mapping) + E1
  wmiprvse→child + window.
- **Negative/control path:** denied (`4625`/access denied) → dừng khai thác; E1 missing trên FS01 → `SENSOR GAP`
  ghi rõ, không đoán; ProcessGuid rỗng ở E3 → hạ mức `TEMPORAL/CONTEXTUAL ONLY`.
- **Acceptance:** bốn câu hỏi completion gate (plan.md:466–474): process chạy trên FS01 (E1), identity (S4624
  account+LogonId), process nào (rundll32 + DLL hash), callback từ FS01 (xem H6). Tất cả cùng run ID.
- **Evidence status:** `NARRATIVE ONLY` (M-41/42) — phải chạy lại run mới có raw evidence khi user duyệt.

### H6 — Remote process → benign DLL → second session (P7 đóng cổng)
- **Precondition:** `ART-06-01` verified; DLL surrogate (benign, unsigned như lịch sử invalid cert D574/D8B3 —
  `[LAB ASSUMPTION]`), không injection vào Winlogon/svchost thật (lịch sử injection là anchor; lab chỉ surrogate
  lab-owned context, telemetry-only cho E10).
- **Input contract:** remote process evidence; DLL path/export từ `ART-04-02.allowed_actions`.
- **Action scope:** DLL thực hiện theo thiết kế `docs/payloads-and-c2.md` §6: (1) GET `/dl/<dll>` từ C2-SIM (T1105),
  (2) POST `/session/register` {host=FS01, stage=phase7-session2, token tự sinh}, (3) GET `/task/next` → thực thi
  **task cố định benign** (ví dụ `T-DISCOVER-CORPUS`: ghi danh sách file corpus), (4) POST `/result` → server tạo
  `ART-07-01`.
- **Expected telemetry:** E1 (rundll32 child wmiprvse), E7, E11, E3 (callback → 192.168.50.1:8080, chú ý ProcessGuid
  có thể rỗng — xác minh), S4624/4672; server-side log C2-SIM + `ART-07-01`.
- **Output contract:** `ART-07-01` (registration receipt **server-side**) + `ART-07-02` (callback telemetry). Marker
  trên FS01 là phụ, không đủ.
- **Detection/correlation:** `C-SESSION2`: FS01 E1 rundll32 (parent wmiprvse) + E7 (hash DLL) + E3→C2-SIM +
  server receipt; join keys: host=FS01, run_id, time window, LogonId từ `ART-06-01`; mức tối đa `SUPPORTED PHASE
  HANDOFF` (artifact producer/consumer có evidence), không đòi `DIRECT EVENT LINK` nếu E3 thiếu ProcessGuid.
- **Negative/control path:** DLL chạy nhưng không register (server không nhận POST hợp lệ) → không tạo receipt →
  P7 `PARTIAL`; control run: load DLL không phải qua WMI (từ cmd) → không được tính session 2.
- **Acceptance (6 tiêu chí theo handoff §9.4):** session WS01 active; WMI handoff approved+evidenced; DLL chạy
  lab-owned context; FS01 register session 2 (receipt); cả 2 session visible (telemetry); mọi linkage hỏng ghi
  partial. **Không đóng P7 từ marker/callback đơn lẻ.**
- **Evidence status:** `NOT VERIFIED` (M-42/43) — run mới bắt buộc.

### H7/H8 — Session → collection → staging → sink
- **Precondition:** `ART-07-01` verified; corpus định trước (Finance: budget-q3.txt, payroll-notes.txt,
  server-inventory.txt — README), ACL đã biết.
- **Input contract:** `ART-07-01` (session 2 token) + `ART-04-02.allowed_actions` (collect_finance_corpus).
- **Action scope:** từ session 2 FS01: đọc file corpus (mirror T1039), tạo `ART-08-01` staging manifest, chuyển sang
  sink qua HTTP POST (surrogate Rclone; **không** real MEGA; không bwlimit thật — T1030 fidelity partial ghi rõ).
- **Expected telemetry:** FS01 S5145 (nếu audit share), E11 staging; host sink log (`p5_sink.py` hiện có);
  E3 transfer nếu capture được.
- **Output contract:** `ART-08-01` + `ART-09-01` receipt; **kiểm tra chéo hash**: hash trong receipt == hash trong
  manifest == allowlist sink (`DEAD1ABD…D15B` đã verify 32-B file).
- **Detection/correlation:** C4 (share → collecting process → outbound transfer): join S5145 (FS01) + E11 staging +
  sink receipt; cần field user.name/host.
- **Negative/control path:** hash lệch allowlist → sink trả 403 (đã có trong `p5_sink.py`) → ghi `PREVENTED`;
  control run: người dùng thường đọc share (không staging/sink) → C4 không fire.
- **Acceptance:** 32-B sink file + receipt + manifest cùng run ID; **không suy ra toàn bộ VM chain từ sink artifact**
  (M-33 giới hạn).
- **Evidence status:** sink-side `ARTIFACT VERIFIED`; VM-side `NOT VERIFIED`.

### H9–H13 — RDP / precursor / impact — chỉ nối khi dependency verified
- **Gate:** H9 (RDP) chỉ chạy khi `ART-07-01` hoặc `ART-09-01` verified (theo milestone chọn); H11 (AnyDesk-like +
  ProcessAccess analysis) chỉ **phân tích telemetry**, không dump LSASS (ranh giới M-11/P11); H12/H13 (impact) chỉ khi
  `ART-12-01` manifest được duyệt với allowlist/caps (plan.md:602–626) + có `ART-14-01` restore verification.
- **Acceptance chung:** mọi phase này có acceptance riêng trong `docs/implementation-plan.md` (items P4-*).

### H14 — Analyst reconstruction (P15 investigation run)
- Ground truth = orchestration/run ledger (`evidence/run-ledger/RUN-<id>.json`); **analyst chỉ nhận telemetry**;
  scorecard so sánh bản dựng lại với run ledger sau khi hoàn tất. Ledger không bao giờ được là nguồn telemetry
  endpoint thay thế (ghi rõ mỗi bước: input/status/output + evidence_links).

## 3. Quy tắc negative/control chung

- Mọi phase có **ít nhất một control run** (hành vi benign tương đương) và **một variation** (đổi một observable) —
  ghi theo loop 13 bước của `docs/plan.md:774–801`.
- Input không hợp lệ / target không tìm thấy / quyền không đủ / sensor không ghi → trạng thái tương ứng
  (`PREVENTED`, `NOT RUN`, `DENIED`, `SENSOR GAP`) — không tự nâng thành PASS.
- Không soft-code: nếu `ART-04-02` không có, P6 không có lý do target — dừng chain tại đó.

## 4. Evidence status tổng hợp theo handoff

| Handoff | Producer | Consumer | Trạng thái hiện tại | Điều cần để `SUPPORTED` |
|---|---|---|---|---|
| H1 | P1 | P2 | `VERIFIED IN REPO` (P1-A/C); hop mshta `PARTIAL` | Raw E1 cho hop mshta + run ID |
| H2/H3 | P3/P4 | P4 | `NOT RUN` (artifact chưa tồn tại) | Run P4 + `ART-04-01/02` |
| H4/H5 | P5/P6 | P6 | `NARRATIVE ONLY` | Exports S4648/4624/4672 + LogonId |
| H6 | P6/P7 | P7 | `NARRATIVE ONLY` / `NOT VERIFIED` | Run mới + `ART-07-01` receipt |
| H7/H8 | P7/P8 | P9 | sink `ARTIFACT VERIFIED`; VM `NOT VERIFIED` | Run collection + staging manifest + receipt |
| H9 | P9/P10 | P11 | `NOT VERIFIED` (DET-008 undefined) | Định nghĩa DET-008 + exports |
| H10–H14 | P11–P15 | — | `NOT RUN` | Theo implementation plan |
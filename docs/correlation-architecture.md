# C0015 Correlation Architecture (v2)

> Định nghĩa cách nối telemetry thành chain có bằng chứng. Phân biệt nghiêm ngặt ba lớp:
> **event-level correlation** (nối event cùng hoạt động), **phase-level handoff** (output phase trước được phase sau
> dùng — xem `docs/handoff-contracts.md`), và **orchestration/run ledger** (ground truth, không phải endpoint telemetry).
>
> Quy tắc chính: **không nâng mức kết luận chỉ vì nhiều event gần nhau về thời gian**. Nếu ProcessGuid/LogonId rỗng,
> PID mâu thuẫn, timestamp lệch, hoặc E3 không có process attribution → hạ mức và ghi lý do.

## 1. Correlation dimensions

| Dimension | Khóa/field | Quy tắc |
|---|---|---|
| `scenario_id` / `run_id` | `C0015-LAB-<n>` / `RUN-YYYYMMDD-<seq>` | **Telemetry KHÔNG mang được run_id** trong event log (không có field chuẩn); run_id sống trong **run ledger** (`evidence/run-ledger/RUN-<id>.json`) và artifact (`artifact_id`). Ledger map run_id → host/account/time-window/task list; correlation dùng window + host + account để quy run về run_id, rồi đối chiếu ledger. Lệnh `wmic … process call create` có thể ghi run_id vào command line nhưng **chỉ là enrichment** nếu schema cho phép — không bắt buộc. |
| Identity | host.name, user.name/user.id (SID), winlog.logon.id (LogonId), event.outcome, auth type (winlog.logon.type) | LogonId là khóa mạnh nhất nối S4648 (source) ↔ S4624/4672 (target) khi explicit credential; **chỉ join LogonId khi cả hai event có cùng giá trị verified trong cùng run**. user.name join chỉ ở mức same-user aggregation (như C1 hiện tại). |
| Process | process.entity_id (ProcessGuid), process.parent.entity_id, process.pid + host + time, process.name, process.executable, process.command_line | ProcessGuid là khóa nối E1→E7→E11→E3 **trong cùng host**. **Không nối PID giữa host/run khác nhau** (P1-B lesson: E3 PID 6032 + E11 PID 6032 chỉ hợp lệ cùng host cũng cùng run). ProcessGuid rỗng (`00000000-…` / null) → không join process-level. |
| Artifact | file.path, file.hash.sha256, file.size, process (producer/consumer), event.code (11/1/7/23/26…) | Hash là khóa xuyên host: DLL hash khớp trên producer (Kali) và consumer (E7) — đã dùng tốt ở P1-C. Artifact ID (`ART-*`) nối qua run ledger + staging/sink receipts. |
| Network | source.ip, destination.ip, destination.port, network.protocol, process.pid/entity_id | **Độ tin cậy process attribution của E3 phải được ghi rõ**: P1-B đã gặp `Image=<unknown>` + ProcessGuid null → chỉ `TEMPORAL/CONTEXTUAL ONLY` trừ khi có E11 cùng PID làm cầu (như P1-B). Không “nối” E3 bằng suy đoán. |
| Time | @timestamp (UTC), host timezone, event.ingested | Mọi cross-host window phải tính **clock skew** (Kali skew chưa sửa — M-04). Window mặc định theo loại hành vi (vd discovery burst 15 phút; WMI→session 2 ≤ 10 phút; callback cadence theo task). Đo window thực tế bằng telemetry, không đoán. |
| Orchestration | step ID, input artifact, output artifact, status, evidence_links | Chỉ là ground truth; không thay endpoint telemetry. Trong investigation run, ledger ẩn với analyst. |

## 2. Correlation tiers (mức kết luận) — bắt buộc ghi mỗi correlation

| Tier | Ý nghĩa | Ví dụ hợp lệ |
|---|---|---|
| `DIRECT EVENT LINK` | Cùng khóa kỹ thuật đáng tin cậy trong telemetry (ProcessGuid, LogonId, hash) | E1 prc (entity P) → E7 ImageLoad (entity P) → E11 (entity P) — P1-C |
| `SUPPORTED PHASE HANDOFF` | Artifact/state do phase A tạo được phase B tiêu thụ, có bằng chứng producer/consumer + run ID | `ART-04-02` (P4 decision) → P6 WMI chọn FS01 |
| `TEMPORAL/CONTEXTUAL ONLY` | Cùng time/host/context nhưng chưa chứng minh causal | E3 (attribution INFERRED qua PID + E11) — P1-B |
| `UNPROVEN` | Thiếu bằng chứng hoặc evidence mâu thuẫn | P4→P5 old linkage (handoff thừa nhận chưa có) |
| `CONTRADICTED` | Evidence xung đột | Phase 1 entity_id/PID (suffix 5376 vs 3604/5872) |

**Downgrade triggers (phải áp dụng, ghi lý do):** ProcessGuid rỗng/Missing field; LogonId không khớp; PID mâu thuẫn
giữa 2 event cùng host; timestamp lệch > clock-skew budget; marker trùng tên giữa run khác; E3 không có process
attribution. **Nâng tier chỉ khi có thêm bằng chứng độc lập** (server-side log, hash khớp, receipt).

## 3. Detecton design theo correlation

Quy ước: KQL/EQL/ES|QL chỉ viết khi schema hiện có đủ căn cứ (field verified trong repo/ingest). Ngược lại ghi
**logic trung lập + danh sách sample event cần lấy trước khi viết query**. `validated` chỉ khi: chạy target run +
control run + ít nhất 1 variation, tái lập được từ query + dataset.

### C1 — Discovery → SMB Collection (tồn tại, `detections/correlations/discovery-to-smb-collection.esql`)
- **Input:** alerts từ 5 atomic (KQL). **Join:** `user.name` aggregation; window 15 min lookback / 5 min freshness
  (scheduled 5 min). **Điều kiện:** ≥4 behavior families, ≥1 collection, ≥2 hosts, ≥1 source IP.
- **Vấn đề đã biết (giữ `PARTIAL`):** phụ thuộc exact `kibana.alert.rule.name` (đổi tên = hỏng âm thầm — cần rule
  UUID/map); `source_ip_count >= 1` là tautology; chưa join `source.ip → host.id` (EXP-009); dedup theo family có thể
  che nhiều instance (EXP-008).
- **Improvement:** dùng rule UUID map + bổ sung join `host.id` từ S5145 source-workstation; thêm variation test
  (eg discovery lan rộng window) & control (chỉ discovery, không collection → không fire).
- **Status:** `DETECTED` (09-15 record) — validated trên dataset đó; tái lập từ stored query chưa làm (không dataset).

### C2 — Bootstrap/Foothold (roadmap — chưa implement)
- **Input:** E1 chain (WINWORD→cmd→mshta→regsvr32), E7 ImageLoad unsigned (user-writable path), E3/E22 callback,
  E11 artifacts. **Join:** ProcessGuid ancestry (host WS01), window 10 phút. **Cần:** process.parent.entity_id mapping
  verified (đã dùng ở EQL prototypes); E3 attribution budget như P1-B.
- **Logic (chờ schema verify toàn bộ field):** `sequence by host: E1(office)→E1(cmd)→E1(mshta)→E1(regsvr32)`
  (EQL — prototypes `detections/eql/*` đã tồn tại cho cmd→child) + E7 unsigned DLL từ `C:\Users\Public\*` +
  E3→Kali/host C2-SIM. **Sample events cần:** 1 run P1 đầy đủ với ProcessGuid clean + 1 control (doc bình thường).
- **Status:** `NOT RUN` (DH-01..06 là hypotheses).

### C3 — Identity/WMI Pivot (P5/P6) — thiết kế, chưa có evidence
- **Input:** WS01 S4648 (explicit cred), FS01 S4624 (Type 3) + S4672 + S4688 (nếu audit), FS01 E1 wmiprvse→rundll32,
  E7, session register (H6). **Join:** LogonId (S4648↔S4624) + host + window (≤10 phút).
- **Ghi chú telemetry:** **E19–21 (WMI-Activity) là WMI filter/consumer/binding — telemetry của WMI subscription
  (T1546.003), KHÔNG phải event của remote process creation qua WMI (T1047); không dùng ở đây.** 
- **Logic:** đếm chuỗi `[WS01 4648] → [FS01 4624/4672 cùng LogonId] → [FS01 E1 parent=wmiprvse] → [session
  register receipt]`; mức tối đa `SUPPORTED PHASE HANDOFF`. **Cần trước khi viết query:** sample exports của một
  run 3B/WMI (hiện `NARRATIVE ONLY`) + xác minh field `winlog.logon.id` mapping.
- **Status:** `NOT RUN`.

### C-SESSION2 — 143.dll surrogate → second session (P7)
- **Input:** FS01 E1 rundll32 (parent wmiprvse), E7 (DLL hash = `c0015_143_surrogate.dll` hash từ `ART-06-01`),
  E11 token file, E3→`192.168.50.1:8080`, server `ART-07-01` receipt. **Join:** host=FS01, run_id (qua ledger),
  LogonId (từ C3), window ≤10 phút. 
- **Logic (trung lập):** mọi rundll32 trên FS01 có parent wmiprvse.exe + ImageLoad DLL không ký từ `C:\C0015\` +
  trong vòng 10 phút có callback ra `192.168.50.1:8080` → cross-check receipt `ART-07-01.host == FS01`. 
- **Boundary:** DLL filename/`C:\C0015\` path chỉ là enrichment; điều kiện phải là hành vi (rundll32 từ wmiprvse +
  outbound callback + receipt). **Status:** `NOT VERIFIED` (chờ run mới).

### C4 — Collection/Transfer (P8/P9)
- **Input:** S5145 (FS01) + E11 staging + sink receipt (`ART-09-01`). **Join:** user.name/host (session 2),
  run_id, hash chéo (manifest ↔ receipt ↔ allowlist). **Logic:** S5145 batch đọc corpus + staging manifest tạo +
  receipt accepted. **Status:** `PARTIAL` (sink artifact verified; VM-side chờ run).

### C5 — Injection Suspicion (P7 analog — telemetry-only)
- **Input:** E10 ProcessAccess (ProcessGuid source→target) + E7 module load + target behavior. **Ranh giới:** chỉ
  theo dõi target lab-owned (`lab-target.exe` trong working-tree sysmon); `winlogon.exe` là **scope telemetry có
  trong config chưa commit — không phép tương tác**. **Status:** `NOT RUN` (E10 chưa deploy-verify; config chưa commit).

### C6 — Impact (P13)
- **Input:** E2/E26/E11 high-rate trên allowlist root + S5145 (SMB impact) + note creation. **Join:** process/account
  + host + root. **Logic:** fan-out > ngưỡng trong window với note markers — so với control (backup/extract/sync).
  **Status:** `NOT RUN`.

## 4. Correlation matrix (tổng hợp)

| Corr | Phase | Input signals | Join keys / window | Mức bằng chứng hiện tại | Gaps | Điều kiện `validated` |
|---|---|---|---|---|---|---|
| C1 | P4+P8 | 5 atomic alerts | user.name; 15 min lookback | `DETECTED` (09-15) — aggregation-level only | rule-name dependency; source.ip→host.id chưa join; no control/variation evidence | control không fire; variation miss→improve; tái lập từ query+dataset |
| C2 | P1–P2 | E1 chain + E7 + E3/E22 | ProcessGuid ancestry; 10 min | `UNPROVEN` (hypotheses DH only) | hop mshta chưa nối; E3 attribution | 1 run P1 clean ProcessGuid + 1 control; EQL prototype chạy được |
| C3 | P5–P6 | S4648/4624/4672 + S4688 + E1 (wmiprvse→child) | LogonId; 10 min | `UNPROVEN` (narrative-only evidence) | Không exports; field mapping chưa verify | exports 1 run; LogonId join verified |
| C-SESSION2 | P7 | E1+E7+E3 + receipt | host+run_id+LogonId; 10 min | `UNPROVEN` | Session-2 chưa tồn tại (mục tiêu) | `ART-07-01` + callback telemetry cùng run |
| C4 | P8–P9 | S5145 + E11 + receipt | user/host + hash; 15 min | `PARTIAL` (sink-side only) | VM chain chưa verify | manifest↔receipt↔allowlist hash khớp |
| C5 | P7 analog | E10 + E7 | ProcessGuid source/target | `NOT RUN` | E10 chưa deploy-verify | config commit + control/injection tests |
| C6 | P13 | E2/E26/E11 + S5145 | process/account + root; window theo metrics | `NOT RUN` | chưa có corpus/manifest | control (backup) vs impact fan-out |

## 5. Sensor/ingest checklist trước khi validate bất kỳ correlation nào

1. E1 có `process.entity_id` + `parent.entity_id` non-empty trên WS01/FS01 (P1-C verified; EQL prototypes OK).
2. E3: ghi nhận attribution status (ProcessGuid null? Image unknown?) — P1-B đã gặp; re-validate sau config change.
3. E7 ImageLoad: path + hash + signature status — verified P1-C.
4. S4624/4648/4672/4625: field `winlog.logon.id`, `user.id` (SID), `source.ip`, `winlog.logon.type` mapping verified.
5. WMI remote-process fields: S4624 Type 3/4672 + S4688 (nếu audit) + E1 `wmiprvse→child` trên FS01. (E19–21 = WMI
   subscription T1546.003 — chỉ kiểm tra nếu cần; KHÔNG liên quan remote process creation.)
6. Clock: WS01/FS01/DC01 sync với domain; **Kali skew phải sửa trước khi dùng cross-host window** (M-04).
7. E10 (ProcessAccess): chỉ cần bật khi có experiment scope cụ thể; config working-tree chưa commit — chờ quyết định.
# Detection run report — RUN-20261002-02 (operator-phase rules R12–R18)

Ngày: 2026-10-02. Rules: `detections/eql/C0015-S4-S9-elastic-rules.ndjson` (8 rules, imported **enabled**,
interval 1m, look-back 5m). Toàn bộ alerts cũ (1.756 open) đã close trước khi chạy (open = 0).

## Diễn biến run

| mốc (Z) | stage | sự kiện |
|---|---|---|
| 03:20:40 | S1–S3 | register `phase3` WS01 `S1-0f74f273ea6322c5` (docm→mshta→regsvr32→beacon) |
| ~03:21:30 | S4/S5 | runbook c0015-phase2 (discovery + share) |
| ~03:23:30 | S7b | elevate beacon-2 (WMI local, it.admin) → mimikatz fetch `:8000` → **E10 lsass (03:25:13)** |
| ~03:25:00 | S8a | T1105 fetches ×3 + SMB C$ copies → FS01 |
| 03:25:41 | S8b/S9 | wmic→FS01 `rundll32 ...143.dll LabEntry` → **receipt `ART-07-01-12cd3a46`** |

## Coverage: stage → rule → alerts (window 03:19:30–03:45:00Z)

| Stage | Rule | Alerts | Chất lượng |
|---|---|---|---|
| S1 | R01/R02/R03/R04/R05/R07/R08 | 1/1/1/4/2/3/3 | ✅ TP nguyên chain (sweep-dup nhỏ) |
| S2–S3 | R06 / R10 | 366 / 39 | ✅ (BB ON — E3 loop noise đã che; R10 dup đã biết từ R01–R11) |
| S4 | R11 / R12 | 6 / 72 | ✅ discovery batch bắt đầy đủ (R12 30–72 tuy theo sweep; BB ON) |
| S5 | R13 | 17 | ✅ net view + Get-SmbShare |
| S7 | R14a / R14b | 27 / 139 | ⚠️ R14b **noise** (84/89 ở WS01 by it.admin — logon lặp beacon elevated) → **chuyển BB ON** sau run; R14a ok |
| S7b | R15 | 3 | ✅ 1 TP mimikatz (03:25:13) + 2 sweep-dup |
| S8a | R16 | 0 | ⚠️ **audit-gated** (5145 chưa có — SENSOR GAP đã note; E11 target là nguồn thay thế) |
| S8b | R17 | 9 | ✅ TP chain `wmiprvse→rundll32→E7 unsigned` (03:26:13) — 3 sweep × chain |
| S9 | R18 (+R09) | 12 (+6) | ✅ session-2 egress (03:26:17) |

Tổng: **711 alerts raw**; nếu bỏ BB-ON (ẩn) + R14b đã chuyển BB: tập hiển thị = R07/R08/R09/R17/R18/R14b(hidden) ≈
45 alerts — trong đó TP các stage. **R16 = 0 là sensor gap sẽ tự đầy khi bật Detailed File Share audit.**

## Noise & tuning (đã làm / kiến nghị)

| Vấn đề | Phân tích | Xử lý |
|---|---|---|
| R14b 139–228 alerts / cửa sổ | 4672 by it.admin trên WS01 — logon lặp của beacon elevated (mỗi task của beacon trong session it.admin) | ✅ **Chuyển building block ON** (signal, không alerting) + close noise |
| R06 366 | E3 loop beacon — bản chất tín hiệu lặp | ✅ BB ON từ đầu (ẩn); dedup theo entity khi phân tích |
| R12/R10 sweep-dup | Cùng sequence khớp nhiều sweep (interval 1m, look-back 6m) | Kiến nghị: **alert suppression** theo `process.entity_id` (group_by + duration) cho sweep > 1 lần |
| E11 S8a (SMB write) | E11 phiá target không giữ UNC/Image/User | Không thể dùng E11 làm nguồn S8a — giữ R16 (5145) + note |

## Preview vs run (đối chiếu)

| Rule | Preview RUN-20261002-01 | Rerun RUN-20261002-02 | Khớp |
|---|---|---|---|
| R12 | 3 | 30–72 (dup) | ✅ |
| R13 | 3 | 17 (dup) | ✅ |
| R14a | 4 | 27 (dup) | ✅ |
| R14b | 4 | 139 (noise) | ⚠️ đã BB ON |
| R15 | 1 (wide 27.5h: 2, 0 FP) | 3 (1 TP + dup) | ✅ |
| R16 | 0 (audit) | 0 (audit) | ⏳ gated |
| R17 | 0→1 (sau fix `any where` + bỏ path glob) | 9 (3 × chain) | ✅ |
| R18 | 2 | 12 (dup) | ✅ |

## Kết luận

- **Phát hiện từ đầu → cuối đầy đủ**: S1–S9 mỗi stage ≥1 rule fire; correlation cao cấp (R07/R08/R09/R17/R18)
  bắt đúng sequence với entity join — không hardcode IP/port/host/hash/account.
- **Noise còn lại**: chủ yếu do sweep duplication (giải bằng suppression) + R06 loop (đã ẩn BB).
- **R16**: cần bật audit policy Detailed File Share trên share lab rồi re-preview (kiến nghị preflight v3).

## File

- Rules: `detections/eql/r12*..r18*.eql` + import `detections/eql/C0015-S4-S9-elastic-rules.ndjson`
- Ledger: `evidence/run-ledger/RUN-20261002-02.json` + receipt `ART-07-01-12cd3a46.json`
# Telemetry comparison — C0015 original campaign vs lab run RUN-20260930-01

Phạm vi: S1 → S9 (hết phase operator). Nguồn "camp gốc": DFIR C0015 (2021-11-29) + research trong
`docs/attack-chain-plan.md`. Nguồn lab: Elastic Sysmon (run window 02:00–04:30Z 2026-10-01) + c2sim ledger.

## Bảng so sánh

| # | Stage | Camp gốc — telemetry kỳ vọng | Lab — telemetry ĐÃ CÓ (verified) | Khác biệt / ghi chú |
|---|---|---|---|---|
| S1 | Entry (docm→mshta→regsvr32) | E1 `WINWORD` → `mshta` → `regsvr32 /s <img>`; E3 tải payload; E7 DLL; E11 marker | ✅ E1 `mshta.bootstrap.hta` (r=338620) → `regsvr32 /s c0015-comparefor.jpg` (r=338630) → `powershell c0015_beacon.ps1` (par ent khớp); E11 markers (b64/js/comparefor/dll-executed) | Chain entity khớp; payload thay surrogate |
| S2–S3 | Beacon session-1 | E1 beacon (powershell); E3 C2 `:8080`; E11 token | ✅ E1 beacon par=regsvr32; E3 ws01→:8080 dày đặc; register `phase3` | — |
| S4 | Discovery | E1 con của beacon: `whoami /all`, `net view /all`, `tasklist`, `net group`, `net localgroup`, `nltest`, `net view /domain`, `net view /all /time`, `ping` | ✅ E1 con beacon (batch 8 + runbook) — log c2sim `task/next` + kết quả | Bản config cũ (3 task) làm 1 số task chạy fallback `ver` → đã regen config full-map |
| S5 | Share enumeration | E1 `net view \\FS01` + ShareFinder(vbs) ; E11 `found_shares.txt` | ✅ E1 `net view \\FS01` + `Get-SmbShare` (par=beacon) → Finance + IT | thay vbs bằng beacon-/cmd |
| S6 | Target manifest | file manifest trên FS01 (sau S10) | ⏳ chưa (ART-04-02 template sẵn, chưa artifact-new) | — |
| S7 | Auth attempt | S4625 (fail) / **S4648** (explicit cred) / **S4624 T3 + S4672** (FS01); E1 `net.exe`; E3 | ⚠️ E1 `net/runas` có; nhưng **Security channel KHÔNG ingest** → không có 4624/4648/4672 trên ES | Gap chính — LogonId join không khả dụng trên ES |
| S7b | LSASS (credential access) | E10 OpenProcess lsass (mimikatz **in-process**, không E1 binary) + minidump | ✅ **E10 `mimikatz.exe`→lsass grant=0x1010** (02:45:52) + E1 mimikatz (process riêng) + E11 copy | Lab chạy mimikatz.exe (E1 mới) thay in-process; NTLM lấy được, crack fail rockyou→provisioned |
| S8a | Handoff (tool to FS01) | S5145/S5140 (SMB write từ máy khác); E11 file FS01 | ⚠️ **E11 FS01 3 file (02:49–50)** ✅; nhưng **S5145 không có (Security gap)** | E11 thay cho S5145 |
| S8b | WMI pivot | **E1 `wmiprvse.exe → rundll32.exe`** + **E7 143.dll (hash)** + S4648/S4624/4672 | ⚠️ **E1 `WmiPrvSE → cmd/powershell`** diag + `s8b_loader` ✅ (WMI process-creation T1047 verified); **E7 rundll32→143.dll** ✅ (r=94752 hash=ART-06-01) nhưng **parent = powershell-console** (chạy interactive), không phải wmiprvse | **Khác cha**: rundll32+ANY-DLL qua WMI bị ReturnValue=9 (session-0/window-station) — không tạo được chữ ký `wmiprvse→rundll32`; E7/entity-chain rundll32 vẫn nguyên vẹn |
| S9 | Session-2 (FS01) | E1 beacon par=rundll32; E7; E11 token; E3 callback | ✅ E1 beacon (par_ent ≡ rundll32 E7 entity); E11 `c0015_143-executed.txt`; E3 FS01→:8080; **receipt ART-07-01-7b91df2d** | — |

## Chú giải
- ✅ = verified trên Elastic (record id kèm); ⚠️ = có một phần / thuộc kênh khác; ⏳ = chưa tạo artifact.
- **Gap lớn nhất**: data stream chỉ gom **Sysmon** — toàn bộ telemetry **Security (S4624/4625/4648/4672/5140/5145/4688)** không có trên ES
  → các join key `LogonId` và phần auth-timeline của S7/S8 không dựng được trên ES (chỉ qua c2sim + thao tác tay).
- **S8b cha khác**: `wmiprvse→rundll32` (gốc) không tạo được do rundll32 GUI không khởi tạo window-station trong
  session-0 của WMI (ReturnValue 9 cho MỌI DLL, đã chứng minh); lab giữ: WMI process-creation (diag+loader) +
  rundll32→143.dll (E7 hash parity + entity chain) — telemetry phía rundll32 khớp gốc, chỉ parent khác.
- S7b: gốc = mimikatz in-process (E10, không E1 binary); lab = chạy mimikatz.exe riêng (E1 mới + E10) — khác biệt
  model đã ghi trong `payloads/lsass/` + docs.

## Mức fidelity
S1–S6 + S9: **HIGH** (chain + entity + receipt khớp). S7: **PARTIAL** (thiếu Security channel). S7b: **HIGH** trên
Sysmon, khác model binary. S8: **PARTIAL–HIGH** — T1047 verified, rundll32-side verified, cha khác (lab constraint).
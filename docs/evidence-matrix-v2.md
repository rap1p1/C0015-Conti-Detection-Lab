# C0015 Evidence Matrix v2

> Canonical evidence ledger. Supersedes ad-hoc claims in handoffs. **A claim is only `[OBSERVED]` when it has a
> verified source (repo file+line, committed artifact, hash, raw event export).** Everything sourced only from the
> narrative handoff (2026-09-26) is `NARRATIVE ONLY` until raw evidence is supplied.
>
> Evidence label mapping (từ 2026 — dùng nhãn mới, giữ ý nghĩa): `[OBSERVED]` ≡ `[OBSERVED-C0015]`
> (nguồn trực tiếp campaign); `[INFERRED]` ≡ `[INFERRED-C0015]`; `[UNKNOWN]` ≡ `[UNKNOWN-C0015]`;
> `[LAB ASSUMPTION]` ≡ `[LAB-SURROGATE]`; bổ sung `[SUPPLEMENTAL-LAB-TECHNIQUE]` (technique do thiết kế lab,
> không phải hành vi C0015) và `[NOT-VERIFIED-IN-REPO]` (narrative-only). Narrative chain đầy đủ:
> `docs/attack-chain-plan.md`.
>
> Status vocabulary: `VERIFIED IN REPO` (repo file/commit/hash), `ARTIFACT VERIFIED` (on-disk artifact with hash),
> `NARRATIVE ONLY` (handoff/agent memory), `NOT VERIFIED`, `NOT RUN`, `PARTIAL`, `SENSOR GAP`,
> `INGEST/MAPPING GAP`, `DETECTION MISS`, `DETECTED`, `CONTRADICTED`.
>
> Run IDs: none of the existing evidence carries a trustworthy run ID (audit 2026-09). Every existing claim keeps
> `run ID: (none recorded)`; future claims must carry `RUN-YYYYMMDD-<seq>`.

## Matrix rows

Columns: `ID | Sequence/time | Source claim | Evidence reference | Label | Host/account/logon | Process (+parent, ProcessGuid) | Artifact/hash | Network endpoint | ATT&CK | Lab surrogate | Expected telemetry | Detector/correlation | Handoff (in→out) | Run ID | Status`.

### A. Baseline & sensors (P0)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| M-01 | Elastic Agent enrollment + ingest (namespace `c0015`, policy `C0015-Windows-Endpoints`) operational | `docs/lab-journal.md:11–19` (2026-09-12); `docs/architecture.md:82–111` | `[OBSERVED]` (journal) | WS01/FS01 | — | — | — | → tất cả phase | (none) | `VERIFIED IN REPO` (documented; live state chưa re-check) |
| M-02 | Sysmon E1/E3/E11/E22 validated; baseline config IDs 1,3,11–14,17–18,19–21,22 (7/10 absent) | `configs/sysmon/sysmon-c0015.xml` @ `fe41049`; lab-journal 09-12; **handoff 2026-09-26: live EID 1,3,11–14,17–22 on / 7,10 off; live config hash `D30CD93C83E3409F7AA1D45FEDEA2695B9F1481FF1D3DFF019AE2B8F01D99C18`** | `[OBSERVED]` (config committed + live bàn giao) | WS01/FS01 | — | — | — | → P1.. | (none) | `VERIFIED IN REPO` (committed) + live state ghi nhận; **hash live ≠ committed ≠ working-tree → bản thứ ba chưa có trong repo** (xem M-03) |
| M-03 | Working-tree sysmon restructure (chưa commit): bật EID 2,5,6,7(scoped),8,10(scoped, gồm target `winlogon.exe`),15,25,26,29; registry include-only; E3 loại `192.168.50.10:53` | `git diff` working tree (không commit); `git status`; **hash check 2026-10: working-tree=`42BC6998…` ≠ live `D30CD93C…`** | `[OBSERVED]` (diff) — `[LAB ASSUMPTION]` về mục đích telemetry | WS01/FS01 | — | Telemetry config cho injection/impact phases | — | → P7/P11/P13 (dự kiến) | (none) | **Chưa deploy trên máy thật** (live: 7/10 disabled, hash khác); đánh giá là cấu hình telemetry, không phải evidence hoạt động trên `winlogon.exe` (ranh giới: không injection vào Winlogon). **Hệ quả: S2/S9 cần EID 7 → M-1 phải quyết định deploy bản EID 7 scoped** |
| M-04 | Kali clock skew chưa sửa (Windows UTC 02:38 vs Kali 22:38 local) | `docs/lab-journal.md:105`; `evidence/phase1-evidence-index.md:176–181` | `[OBSERVED]` gap | Kali / WS01 | — | — | — | — | (none) | `SENSOR GAP` (cross-host timeline unreliable) |

### B. Phase 1 — entry/bootstrap (repo `fe41049`)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Expected telemetry | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| M-10 | WINWORD.EXE (PID 2288) → cmd.exe (PID 5564) → mshta.exe (PID 6592) | `evidence/phase1-evidence-index.md:9–33`; lịch sử commit `fe41049` | `[OBSERVED]` | WS01, `duc.user` | T1204.002, T1059.003/.005 | `test.docm` macro (trigger thủ công — `[LAB ASSUMPTION]`) | E1 | DH-01/DH-02 (chưa production) | → P1 chain | (none) | `VERIFIED IN REPO` |
| M-11 | E3: PID 6032 → 192.168.50.100:8000, `Image=<unknown>`, ProcessGuid null | `evidence/phase1-evidence-index.md:49–61` | `[OBSERVED]` event; attribution `[INFERRED]` | WS01 | T1105 (vector analog) | Kali HTTP server | E3 | DH-06 (gap analysis) | P1-B | (none) | `VERIFIED IN REPO` (event cited); `SENSOR GAP` attribution |
| M-12 | E11 `downloaded-marker.txt` (mshta, PID 6032) + Kali HTTP 200 `GET /benign.txt` | `evidence/phase1-evidence-index.md:63–81` | `[OBSERVED]` | WS01 | T1105 | benign.txt | E11 + server log | DH-06 | P1-B | (none) | `VERIFIED IN REPO` |
| M-13 | E11 `c0015-marker.dll` (mshta, “PID 3604”, entity `{88E52A21-F5AB-6AAD-CF01-000000001500}`) → E1 regsvr32 (PID 5872) → E7 ImageLoad unsigned DLL → E11 `dll-executed.txt`; SHA-256 `d9622f80c022…544` khớp Kali | `evidence/phase1-evidence-index.md:96–152`; lịch sử commit `fe41049` | `[OBSERVED]` chain; **entity_id/PID `CONTRADICTED`** (suffix `…001500` = 5376 ≠ 3604 ≠ 5872) | WS01, `duc.user`, Medium | T1218.010, T1553.002 (invalid cert) | benign DLL + regsvr32 | E1, E7, E11 | DH-03/DH-04/DH-05 (chưa production) | P1-C | (none) | `VERIFIED IN REPO` (chain + hash); entity/PID `UNRESOLVED` |
| M-14 | E3 cho P1-C DLL retrieval: **không có** | `evidence/phase1-evidence-index.md:163–170` | `[OBSERVED]` absence | WS01 | T1105 | server-side HTTP 200 only | E3 missing | DH-06 | P1-C | (none) | `SENSOR GAP` |
| M-15 | Hop `mshta 6592 → mshta 6032/3604` chưa có parent-child evidence; 3 PID mshta trong 1 chain | `docs/investigation.md:180–223`; evidence index | `[UNKNOWN]` — docs không nối được | WS01 | — | — | E1 | — | P1-A→P1-B/C | (none) | `PARTIAL` — cần raw event |

### C. Discovery & collection (P4/P8, repo `fe41049`)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| M-20 | T1057 tasklist, T1069.002 net, T1482 nltest, T1135 net view, T1039 5145 read — DETECTED | `docs/lab-journal.md:53–71`; `docs/experiments.md` EXP-001..005,008,009 | `[OBSERVED]` (recorded run + alert) | WS01 `duc.user` → FS01 (5145) | T1057, T1069.002, T1482, T1135, T1039 | native utilities | 5 atomic KQL + ES|QL C1 (Medium, risk 60) | P4→P8 old chain | (none) | `VERIFIED IN REPO` (alert record); raw dataset chưa có → tái lập chưa làm |
| M-21 | S5145: `C0015\duc.user`, source `192.168.50.20`, `\\*\Finance`, `budget-q3.txt`, ReadData | `docs/investigation.md:127–157`; lab-journal 09-15 | `[OBSERVED]` | FS01, `duc.user` | T1039 | — | t1039 atomic | EXP-005 | (none) | `VERIFIED IN REPO` |
| M-22 | source.ip → host identity join chưa thực hiện trong C1 | `docs/experiments.md` EXP-009 limitation (dòng 215) | `[OBSERVED]` gap | — | — | — | C1 | — | (none) | `PARTIAL` (documented gap) |
| M-23 | T1018/T1016: repo NOT RUN vs handoff PASS | lịch sử commit `fe41049` vs handoff §6 | `[CONTRADICTED]` | WS01 | T1018, T1016 | ping/ipconfig (claim) | — | — | (none) | `CONTRADICTED` — chờ raw evidence |
| M-24 | Discovery→target artifact (`found_shares`/manifest) chưa tồn tại | toàn repo (không có file/event) | `[UNKNOWN]` | — | T1074.001 | chưa triển khai | — | P4→P6 | (none) | `NOT RUN` |

### D. Host artifacts (ngoài repo, có hash — `ARTIFACT VERIFIED`)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| M-30 | `C:\C0015\c2sim\c2sim.py`: receiver chỉ nhận `192.168.50.30` + `stage=phase4-rundll32` + `host=FS01`; bind `192.168.50.1:8080`; trả 204 | file exists; đọc nội dung (không hash — code) | `[OBSERVED]` (artifact code) | host `192.168.50.1` | T1570 (receiver side) | constrained C2-SIM receiver | — | P6→P7 (candidate) | (none) | `ARTIFACT VERIFIED` (tồn tại; **không chứng minh run**) |
| M-31 | `C:\C0015\c2sim\public-ip.txt` = `203.0.113.77` (TEST-NET-3) | artifact | `[OBSERVED]`; IP `[LAB ASSUMPTION]` | host | T1016 | mock public-IP lookup | — | P2 | (none) | `ARTIFACT VERIFIED` |
| M-32 | `C:\C0015\P5\p5_sink.py`: allowlist SHA-256 `DEAD1ABD…D15B`, max 1024 B, 1 file `/ingest/c0015-p5`, bind `192.168.50.1:8081` | artifact (code) | `[OBSERVED]` | host | T1567.002 surrogate | internal sink | — | P9 | (none) | `ARTIFACT VERIFIED` |
| M-33 | `C:\C0015\P5\sink\received-payroll-notes.txt` (32 B): SHA-256 = `DEAD1ABD…D15B` **khớp allowlist** | `Get-FileHash` (đã chạy 2026-09) | `[OBSERVED]` | host | T1567.002 surrogate | received lab file | — | P9 evidence | (none) | `ARTIFACT VERIFIED` — chỉ sink-side; **không chứng minh VM collection/transfer run** |
| M-34 | DLL surrogate `c0015_143_surrogate.dll` (hash `1C1EF8BA…` theo handoff) | handoff §6; **không có file trên host** (VM-internal expected `C:\C0015\`) | `[UNKNOWN]` | FS01 (expected) | T1218.011 | benign DLL | — | P7 | (none) | `NARRATIVE ONLY` |

### E. Auth bridge / WMI / DLL run / RDP (post-09-19 — tất cả narrative)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| M-40 | Auth bridge “3B”: WS01 4648, FS01 4624 (Kerberos), 4672; `duc.user` denied; LogonId `0xaa63b0` | handoff §6 | `[NARRATIVE ONLY]` | WS01→FS01, `it.admin` | auth/authorization | pre-provisioned credential `[LAB ASSUMPTION]` | — | P5→P6 | (none) | `NARRATIVE ONLY` — cần exports |
| M-41 | WMI canary: `Win32_Process Create` return 0, PID 5752, marker `C:\Windows\Temp\c0015-phase4b.txt` | handoff §6 | `[NARRATIVE ONLY]` | WS01→FS01 | T1047 | WMI native | — | P6 | (none) | `NARRATIVE ONLY` |
| M-42 | DLL branch run: WMI → rundll32 (PID 6100) → `c0015_143_surrogate.dll` → marker → callback; E3 ProcessGuid=0; WS01 4648 missing; FS01 4624/4672 + LogonId `0xaa63b0` | handoff §6 | `[NARRATIVE ONLY]`; E3 attribution `[UNKNOWN]` | WS01→FS01 | T1218.011, T1047 | benign DLL + c2sim | — | P6→P7 | (none) | `NARRATIVE ONLY` — **không hợp nhất PID 6100/5752** |
| M-43 | Second C2-SIM session trên FS01 (revised P7) | handoff §7 (“incomplete”) | `[UNKNOWN]` | FS01 | T1570 | — | — | P7 | (none) | `NOT VERIFIED` — **mục tiêu cần chứng minh** |
| M-44 | DET-008 = successful RDP logon | handoff §6/§7; **không tồn tại trong repo** | `[NARRATIVE ONLY]` | — | T1021.001 | — | DET-008 (undefined) | P10 | (none) | `NOT VERIFIED` |

### F. Impact / recovery / E2E (P12–P15)

| ID | Claim | Evidence ref | Label | Host/account | ATT&CK | Surrogate | Detector | Handoff | Run ID | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| M-50 | Bounded impact design (allowlist root, caps, no propagation, restore) | `docs/plan.md:592–652` | `[OBSERVED]` (design only) | FS01 | T1486 | simulator (chưa tồn tại) | — | P13 | (none) | `NOT RUN` |
| M-51 | E2E engineering + investigation runs | `docs/plan.md:899–941` | `[OBSERVED]` (design only) | toàn lab | — | — | — | P15 | (none) | `NOT RUN` |

## Rules of use

1. **Không nâng mức bằng chứng** từ `NARRATIVE ONLY` lên `VERIFIED` nếu chưa có raw export/hash/event ID trong repo
   hoặc artifact đã verify.
2. **Không gộp event từ run khác nhau**: mỗi run ID riêng; PID chỉ hợp lệ trong cùng host + cùng run + cùng
   window; ProcessGuid rỗng → hạ mức correlation (xem `docs/correlation-architecture.md`).
3. **Marker file ≠ session**: marker chứng minh file được ghi; session/callback phải có registration receipt phía
   server + telemetry callback (E3/E22 có ProcessGuid) độc lập.
4. Mọi row mới phải dẫn nguồn cụ thể (path:line, event ID, run ID, commit, hash). Nếu chưa có, ghi thiếu gì.
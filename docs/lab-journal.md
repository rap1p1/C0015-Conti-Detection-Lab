# Lab Journal

Major milestones for the C0015 Conti Detection Lab.

---

## 2026-09-12 — Telemetry Pipeline Validation

Validated end-to-end telemetry from WS01 to Elastic Security.

**Infrastructure confirmed:**

| Component | Status |
|---|---|
| Elastic Agent enrollment (C0015-Windows-Endpoints policy) | Operational |
| Windows Security event ingestion (namespace `c0015`) | Operational |
| Sysmon installation and Event ID 1 ingestion | Operational |
| Kali Tailscale routing to ELASTIC01 | Operational |

**Validated Sysmon event classes:**

- Event ID 1 — Process Create
- Event ID 3 — Network Connection
- Event ID 11 — File Create
- Event ID 22 — DNS Query

**Sysmon tuning:** Initial visibility-first configuration generated substantial noise from VMware Tools registry activity (`vmtoolsd.exe` accessing `HKLM\...\Tcpip\Parameters`). A targeted exclusion was added for the specific process/path combination. Security-relevant registry telemetry (e.g., `HKCU\...\Run` modifications) remained intact.

**VMware NAT finding:** Elastic Agent connectivity loss traced to stopped VMware NAT Service on the Windows host. Kali `eth1` was down, Tailscale in `NoState`. Resolved by restarting the NAT service. Agent recovered automatically without reinstallation.

---

## 2026-09-14 — Active Directory and File Server Foundation

**Domain:** DC01 promoted to domain controller for `c0015.lab`.

**Identities created:**

- `duc.user` → Finance
- `it.admin` → IT-Admins

**Domain join:** WS01 and FS01 joined to `c0015.lab`. Elastic telemetry confirmed domain identity fields (`user.domain = C0015`).

**FS01 shares configured:**

- `Finance` — `duc.user` has read access
- `IT` — access denied for `duc.user` (as intended)

Benign dummy files created for controlled collection testing.

---

## 2026-09-15 — Discovery and SMB Collection Detection Milestone

**Validated behaviors on WS01:**

- T1057 Process Discovery
- T1069.002 Domain Groups Discovery
- T1482 Domain Trust Discovery
- T1135 Network Share Discovery

**FS01 file-share auditing** enabled for Finance share. Event ID 5145 confirmed remote access from WS01 (`source.ip = 192.168.50.20`) by `C0015\duc.user`.

**Elastic Agent on FS01** enrolled after resolving route, CA trust, token, and daemon-state issues.

**Detection rules created:**

- Five low-severity atomic building blocks
- One ES|QL cross-host correlation: `Suspicious Discovery and Network Share Collection Chain`

**Result:** Medium severity, risk score 60, end-to-end validation PASS.

---

## 2026-09-16 — Repository and Documentation Checkpoint

First detection milestone documented and committed to version control.

- Atomic KQL building blocks stored for T1057, T1069.002, T1482, T1135, T1039
- ES|QL correlation stored for the first analyst-facing detection
- Cross-host investigation logic, noise handling, and telemetry limitations documented
- Repository excludes secrets, enrollment tokens, and private keys

---

## 2026-09-19 — Phase 1 Bootstrap Chain Complete

Phase 1 benign Bazar-stage reconstruction verified end-to-end on WS01.

**Chain validated:** WINWORD.EXE → cmd.exe → mshta.exe → HTTP artifact retrieval → benign DLL written to disk → regsvr32.exe → c0015-marker.dll loaded → DllRegisterServer() → dll-executed.txt marker created.

**Checkpoints:**

| Checkpoint | Description | Status |
|---|---|---|
| P1-A | Office → cmd.exe → mshta.exe | PASS |
| P1-B | HTTP retrieval + network event + artifact creation | PASS |
| P1-C | DLL delivery + regsvr32 execution + ImageLoad + marker | PASS |

**DLL hash continuity:** SHA-256 `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544` verified Kali → WS01 (Sysmon Event ID 7 ImageLoad).

**Known gaps:**

- **Sensor gap:** No Sysmon Event ID 3 captured for the final P1-C DLL network retrieval. Server-side HTTP evidence confirms the transfer occurred; process and file telemetry independently support the chain.
- **Timing:** Kali clock skew remains unresolved. Windows/Sysmon UTC (~02:38 UTC) and Kali HTTP logs (~22:38 local) are not precisely synchronized. Cross-host timestamp comparison is unreliable until corrected.
- **P1-B attribution:** Event ID 3 contained `Image=<unknown process>` with null ProcessGuid. mshta.exe attribution is INFERRED from PID correlation, not direct sensor identification.

**Detection hypotheses documented:** Six analytic opportunities (DH-01 through DH-06) recorded in detection-engineering.md. No production rules claimed.

**Phase 2:** Will begin from this verified Phase 1 baseline. Not implemented in this update.


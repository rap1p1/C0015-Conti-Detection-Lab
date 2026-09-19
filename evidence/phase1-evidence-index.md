# Phase 1 Evidence Index

Evidence index for the Phase 1 bootstrap/Bazar-stage benign reconstruction.

All evidence was collected from WS01 (192.168.50.20) via Sysmon telemetry ingested into Elastic Security, supplemented by Kali (192.168.50.100) server-side HTTP logs.

---

## P1-A — Office → cmd → mshta

### Sysmon Event ID 1 — cmd.exe

| Field | Value |
|---|---|
| Timestamp | Sysmon Event ID 1 on WS01 |
| Image | cmd.exe |
| PID | 5564 |
| Parent Image | WINWORD.EXE |
| Parent PID | 2288 |
| Command line | `cmd.exe /c "C:\Windows\System32\mshta.exe C:\Users\Public\C0015\bootstrap.hta"` |
| Evidence label | OBSERVED |

### Sysmon Event ID 1 — mshta.exe

| Field | Value |
|---|---|
| Timestamp | Sysmon Event ID 1 on WS01 |
| Image | mshta.exe |
| PID | 6592 |
| Parent Image | cmd.exe |
| Parent PID | 5564 |
| Command line | `C:\Windows\System32\mshta.exe C:\Users\Public\C0015\bootstrap.hta` |
| Evidence label | OBSERVED |

### Source document

| Field | Value |
|---|---|
| File | `C:\Users\duc.user\Desktop\test.docm` |
| Type | Word macro-enabled document |
| Trigger | Manual macro execution (controlled lab — not social-engineering delivery) |

---

## P1-B — Benign Network Retrieval

### Sysmon Event ID 3 — Network connection

| Field | Value |
|---|---|
| Timestamp | 2026-09-19T01:23:48.766Z |
| Source IP | 192.168.50.20 |
| Source port | 50039 |
| Destination IP | 192.168.50.100 |
| Destination port | 8000 |
| Protocol | TCP |
| Direction | egress |
| PID | 6032 |
| Image | `<unknown process>` |
| ProcessGuid | `{00000000-0000-0000-0000-000000000000}` (null) |
| Evidence label | OBSERVED (network event); process attribution is INFERRED |

### Sysmon Event ID 11 — FileCreate (downloaded-marker.txt)

| Field | Value |
|---|---|
| Timestamp | 2026-09-19T01:23:52.680Z (CreationUtcTime) |
| Image | `C:\Windows\System32\mshta.exe` |
| PID | 6032 |
| Target file | `C:\Users\Public\C0015\downloaded-marker.txt` |
| Evidence label | OBSERVED |

### Kali HTTP server log

| Field | Value |
|---|---|
| Client | 192.168.50.20 |
| Request | `GET /benign.txt` |
| Response | HTTP 200 |
| Evidence label | OBSERVED |

### Correlation note

Process attribution for the Event ID 3 network connection is INFERRED from:
- PID 6032 match between EID 3 and EID 11
- Temporal proximity (~4 seconds)
- Server-side HTTP evidence
- Causal consistency (downloaded-marker.txt is the expected artifact)

Event ID 3 did **not** directly identify the process as mshta.exe.

---

## P1-C — Benign DLL + regsvr32 Execution

### Sysmon Event ID 11 — FileCreate (c0015-marker.dll)

| Field | Value |
|---|---|
| Image | mshta.exe |
| PID | 3604 |
| ProcessGuid / entity_id | `{88E52A21-F5AB-6AAD-CF01-000000001500}` |
| Target file | `C:\Users\Public\C0015\c0015-marker.dll` |
| Evidence label | OBSERVED |

### Sysmon Event ID 1 — regsvr32.exe ProcessCreate

| Field | Value |
|---|---|
| Timestamp | 2026-09-19T02:38:35.452Z |
| Image | `C:\Windows\System32\regsvr32.exe` |
| PID | 5872 |
| ProcessGuid / entity_id | `{88E52A21-F5AB-6AAD-D001-000000001500}` |
| Parent Image | `C:\Windows\System32\mshta.exe` |
| Parent PID | 3604 |
| Parent ProcessGuid / entity_id | `{88E52A21-F5AB-6AAD-CF01-000000001500}` |
| Command line | `"C:\Windows\System32\regsvr32.exe" /s "C:\Users\Public\C0015\c0015-marker.dll"` |
| User | `C0015\duc.user` |
| Integrity level | Medium |
| Evidence label | OBSERVED |

### Sysmon Event ID 7 — ImageLoad (c0015-marker.dll)

| Field | Value |
|---|---|
| Timestamp | 2026-09-19T02:38:35.469Z |
| Process | regsvr32.exe |
| PID | 5872 |
| ProcessGuid / entity_id | `{88E52A21-F5AB-6AAD-D001-000000001500}` |
| ImageLoaded | `C:\Users\Public\C0015\c0015-marker.dll` |
| SHA-256 | `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544` |
| Signed | false |
| Signature status | Unavailable |
| Evidence label | OBSERVED |

### DLL Hash Continuity

| Location | SHA-256 |
|---|---|
| Kali (before delivery) | `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544` |
| WS01 (Sysmon EID 7 ImageLoad) | `d9622f80c022133f2d060dfb758410413174dfbda69ecd370899c6a361b75544` |
| Match | ✓ |

### Sysmon Event ID 11 — FileCreate (dll-executed.txt)

| Field | Value |
|---|---|
| Process | regsvr32.exe |
| PID | 5872 |
| ProcessGuid / entity_id | `{88E52A21-F5AB-6AAD-D001-000000001500}` |
| Target file | `C:\Users\Public\C0015\dll-executed.txt` |
| Evidence label | OBSERVED |

### Kali HTTP server log

| Field | Value |
|---|---|
| Client | 192.168.50.20 |
| Request | `GET /c0015-marker.dll` |
| Response | HTTP 200 |
| Evidence label | OBSERVED |

### P1-C Network Telemetry Gap

| Item | Status |
|---|---|
| Server-side HTTP evidence | OBSERVED |
| Sysmon Event ID 3 on WS01 | NOT OBSERVED (sensor gap) |

No Sysmon Event ID 3 was found on WS01 for this specific DLL retrieval. This does not invalidate the chain — it is independently supported by FileCreate, ProcessCreate, ImageLoad, and the DLL execution marker.

---

## Timing Limitation

| Source | Approximate time |
|---|---|
| Windows/Sysmon (P1-C) | 2026-09-19 02:38 UTC |
| Kali HTTP server | 18/Sep/2026 22:38 (local) |

Kali clock skew is unresolved. Cross-host timestamps must not be treated as precisely synchronized.

---

## KQL Investigation Queries

Process chain:
```kql
host.name:"ws01" and event.code:"1" and
(
  process.name:"WINWORD.EXE" or
  process.name:"cmd.exe" or
  process.name:"mshta.exe" or
  process.name:"regsvr32.exe"
)
```

regsvr32 execution:
```kql
host.name:"ws01" and
event.code:"1" and
process.name:"regsvr32.exe"
```

Downloaded DLL:
```kql
host.name:"ws01" and
event.code:"11" and
file.name:"c0015-marker.dll"
```

DLL ImageLoad:
```kql
host.name:"ws01" and
event.code:"7" and
file.name:"c0015-marker.dll"
```

Execution marker:
```kql
host.name:"ws01" and
event.code:"11" and
file.name:"dll-executed.txt"
```

Network connections:
```kql
host.name:"ws01" and
event.code:"3" and
destination.ip:"192.168.50.100" and
destination.port:8000
```

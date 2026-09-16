# Attack Emulation

## Scope

This lab reproduces behaviors associated with MITRE ATT&CK campaign C0015 using benign Windows commands, dummy data, and controlled infrastructure. The objective is telemetry and detection validation rather than malware execution.

## Completed behavior set

| Technique | Emulation | Result |
|---|---|---|
| T1059.003 Windows Command Shell | Interactive `cmd.exe` activity | PASS |
| T1057 Process Discovery | `tasklist` | PASS |
| T1069.002 Domain Groups Discovery | `net group "Domain Admins" /domain` | PASS |
| T1482 Domain Trust Discovery | `nltest /domain_trusts /all_trusts` | PASS |
| T1135 Network Share Discovery | `net view \\FS01` | PASS |
| T1039 Data from Network Shared Drive | Read benign files from `\\FS01\Finance` | PASS |

## Active Directory foundation

The domain `c0015.lab` provides realistic identity and trust context. `duc.user` is a member of Finance and `it.admin` is a member of IT-Admins. WS01 and FS01 are domain joined.

FS01 exposes two controlled SMB shares:
- `Finance`
- `IT`

The Finance share contains benign test files including `budget-q3.txt` and `payroll-notes.txt`.

## Telemetry validation strategy

Each behavior is validated in layers:

1. Execute a safe behavior on the relevant endpoint.
2. Confirm the expected Windows/Sysmon event locally.
3. Confirm Elastic ingestion and ECS field mapping.
4. Prototype KQL/EQL/ES|QL logic.
5. Evaluate false positives and temporal constraints.
6. Promote useful logic into an atomic or correlation detection.

## T1039 cross-host validation

T1039 is validated with server-side evidence rather than relying only on the client command shell. FS01 Windows Security Event ID 5145 recorded:

- `user.name = duc.user`
- `user.domain = C0015`
- `source.ip = 192.168.50.20`
- `file.name = budget-q3.txt`
- `file.directory = C:\Shares\Finance`
- successful `ReadData` access

This matters because `type` is implemented internally by an already-running `cmd.exe`; Sysmon Process Create does not generate a new `type.exe` event.

## Safety notes

No real ransomware or Bazar/Conti payload is used. Destructive and malware-specific actions will be emulated only with benign substitutes or documented without execution when necessary.

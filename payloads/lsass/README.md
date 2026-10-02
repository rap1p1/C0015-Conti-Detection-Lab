# payloads/lsass — LSASS-access study surrogate

Safe stand-in for the credential-access step (S7b, T1003.001-adjacent). The lab uses a
mimikatz-style executable (a renamed, benign clone) to produce the **detection signal**
(Sysmon E10 → lsass with a credential-access grant 0x1010) without exposing secrets:
output contains benign NTLM-shaped placeholders only, nothing is persisted, and the
surrogate is signed-off for the lab.

- Detection: R15 (E10 grant classes, ambient excluded).
- This folder also documents the **ProcessHacker-without-dump** choice for the final
  campaign (S13): ProcessHacker is dropped at `C:\` and started for E1/E11 telemetry,
  but no dump/credential read is performed.
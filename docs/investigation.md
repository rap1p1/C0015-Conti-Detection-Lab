# Investigation Notes

## Case: Discovery to SMB Collection

The first analyst-facing detection correlates Windows discovery activity on WS01 with remote file access on FS01.

### Observed chain

1. `tasklist` - process discovery
2. `net group ... /domain` - domain group discovery
3. `nltest /domain_trusts /all_trusts` - domain trust discovery
4. `net view \\FS01` - network share discovery
5. read of `\\FS01\Finance\budget-q3.txt` - network share collection

The discovery activity occurred under `C0015\duc.user` on WS01. The collection evidence was recorded on FS01 by Windows Security Event ID 5145.

## Server-side SMB evidence

The relevant FS01 5145 event contained:
- `user.name = duc.user`
- `user.domain = C0015`
- `source.ip = 192.168.50.20`
- `file.name = budget-q3.txt`
- `file.path = C:\Shares\Finance\budget-q3.txt`
- successful read-related access
## Client-side visibility limitation

The file was read with the interactive `cmd.exe` built-in `type` command. Because `type` is handled inside an already-running command shell, it does not necessarily create a separate process and therefore does not guarantee a new Sysmon Event ID 1.

This is an important visibility lesson: absence of a new process event does not mean the file access was invisible. The server-side SMB audit record provided stronger evidence of the action.

## Cross-host correlation

The final ES|QL rule correlates the discovery alerts on WS01 with collection alerts on FS01 by user and aggregate context. The validated result contained:

- five distinct behavior families
- collection activity present
- two contributing hosts
- a source IP associated with remote access

The final Elastic Security alert was created with Medium severity and risk score 60.

## Analyst interpretation

No single atomic event proves compromise. The value comes from the sequence of multiple discovery behaviors followed by remote data access in a short window. The correlation is therefore intended for analyst triage rather than automatic containment.

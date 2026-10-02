# LSASS-access study surrogate

[c0015_mimikatz_surrogate.c](c0015_mimikatz_surrogate.c) produces a credential-access
**surface** for S7b. It can be packaged as a mimikatz-named executable, but it is not
real Mimikatz and does not extract credentials. The retained runs use this surrogate.

It opens a handle to LSASS with query/VM_READ rights (**0x1010**), then closes it
without reading LSASS memory. It emits benign NTLM-shaped placeholders and writes
a **decoy `lsass.dmp` file**. Therefore “nothing is persisted” is incorrect; the
persisted data is a lab artifact, not extracted memory or a usable credential.
Sysmon E10 records access rights, not their use. R15 detects that access surface.

ProcessHacker's S13 deployment is a separate process-tool observation; it is not
the surrogate source and is not covered by R20's remote-access executable predicate.
Historical ProcessHacker LSASS use remains inferred. Lab pre-provisioned operator
identity must not be presented as a credential recovered by this component.

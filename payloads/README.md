# Laboratory components

These components generate observable campaign-inspired behavior on the owned lab VMs.
Runtime configuration supplies many endpoint/path values, but source files also
contain defaults and lab-specific paths; the implementation is not wholly free of
hardcoded values. Historical fidelity is documented separately from successful execution.

| Folder | Stage | Component |
|---|---|---|
| [docm/](docm/) | S1 | Base macro and generated self-write entry variant |
| [hta/](hta/) | S2 | VBScript decode/download/proxy bootstrap and JScript marker |
| [dll/](dll/) | S2–S3, S8b–S9 | Separate bootstrap and lateral-pivot DLL sources |
| [beacon/](beacon/) | S3/S9 and operator tasks | Registration/task/result agent |
| [lsass/](lsass/) | S7b | LSASS-access surface, placeholder output and decoy dump |
| [impact/](impact/) | S14 | Bounded, reversible dummy-corpus transformation |
| [packaging/](packaging/) | Harness | Build, document installation, configuration and orchestration |
| [config/](config/) | Runtime inputs | Symbolic INI examples |

The generated entry macro writes config/HTA/beacon into the public staging directory;
compiled tools are fetched or staged separately. Do not describe all tools as embedded
in the document. Bootstrap `c0015_bootstrap_dll.c` and pivot `c0015_143_surrogate.c`
have different roles. DLL execution markers are written by the DLL, not the HTA.

C2-SIM uses `/session/register`, `/task/next`, and `/result`; `/cmd` and `/runbook`
provide dynamic operator tasks. The default task stream is not an enforcement boundary
for raw commands. See the [implementation overview](../docs/payloads-and-c2.md).

The HTA's VBScript block uses MSXML `bin.base64`, `MSXML2.XMLHTTP`, and `ADODB.Stream`;
JScript independently writes `js-marker.txt`. This is a lab encoding/scripting
substitute, not proof of an identical original decoder. Current rules and run-specific
acceptance keys serve different purposes. [Reports](../reports/) state what ran.

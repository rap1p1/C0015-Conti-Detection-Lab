# HTA bootstrap

[bootstrap.hta](bootstrap.hta) models scripting, base64 decoding, DLL-as-JPG download,
and regsvr32 proxy execution. It uses two independent language blocks:

| Block | Implemented behavior |
|---|---|
| VBScript | `IniGet` reads the public-path config; `B64Decode` uses MSXML bin.base64; ADODB.Stream writes decoded bytes; MSXML2.XMLHTTP downloads the artifact; WScript.Shell starts regsvr32 |
| JScript | Writes `js-marker.txt` using FileSystemObject when the public staging folder exists |

There is no `atob()` dependency. JScript is not the downloader or base64 decoder in
the committed HTA. The MSXML decoding mechanism is a laboratory choice; do not claim
it was proven identical to the historical payload's implementation.

The base config path is a lab-specific convention; most download/path values are
read from `[bootstrap]`. Missing/incomplete configuration prevents the VBScript
download/proxy path, but the independent JScript marker can still be written when
its directory exists. It is not correct to promise no files from the entire HTA.

Expected telemetry: mshta E1, download E3, artifact/marker E11, regsvr32 E1 and loader
E7. `dll-executed.txt` is produced by the DLL, not by the HTA.

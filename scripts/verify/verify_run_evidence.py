#!/usr/bin/env python3
"""Verify ALL RUN-20260930-01 evidence on Elastic (read-only, env creds).
- full sha256 of FS01 E7 (143.dll) vs ART-06-01 hash
- WS01 foothold E1 entity chain (mshta->regsvr32->beacon powershell)
- FS01 loader E1 chain + E7 + E11 + E3 callback entities
- mimikatz E10 lsass grants + accessor identity
- FS01 E11 of the 3 staged files
Prints report; writes stage/analysis/run-window-evidence.md
"""
import base64, json, os, ssl, urllib.request

ES = os.environ.get("ES_URL", "https://100.77.46.126:9200")
USER = os.environ.get("ES_USER", ""); PASS = os.environ.get("ES_PASS", "")
W0 = os.environ.get("RUN_W0", "2026-10-01T02:00:00Z")
W1 = os.environ.get("RUN_W1", "2026-10-01T04:30:00Z")
ART06 = "CBCD2A8B8137BDEDE43C158FDD8C97268DA88B680C2155B1551FBA86301C8A3D"

def ah():
    if USER and PASS:
        return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (USER, PASS)).encode()).decode()}
    raise SystemExit("no creds")
_ctx = ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = ssl.CERT_NONE

def req(path, body):
    r = urllib.request.Request(ES + path, method="POST", headers=ah())
    r.data = json.dumps(body).encode(); r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=60, context=_ctx) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:400]

def q(filter_body, size=200):
    body = {"query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": W0, "lte": W1}}}, filter_body]}},
            "size": size, "sort": [{"@timestamp": "asc"}]}
    st, b = req("/.ds-logs-windows.*/_search", body)
    return (b.get("hits", {}).get("hits", []) if st == 200 else [])

def hh(s):  # host-independent helpers
    return s

R = []
def P(*a):
    R.append(" ".join(str(x) for x in a))

P("== VERIFY RUN-20260930-01: Elastic evidence (02:00-04:30Z) ==")

# 1) FS01 E7 full hash
ev = q({"term": {"winlog.record_id": "94752"}})
if ev:
    s = ev[0]["_source"]
    fh = s.get("file", {}).get("hash", {}).get("sha256", "")
    P("\n[1] FS01 E7 r=94752 ts=%s" % s.get("@timestamp"))
    P("    img=%s path=%s" % (s.get("process", {}).get("name"), s.get("file", {}).get("path")))
    P("    sha256=%s" % fh)
    P("    ART-06-01=%s" % ART06)
    P("    HASH PARITY: %s" % ("MATCH" if fh.upper() == ART06 else "MISMATCH"))

# 2) WS01 foothold E1 chain (mshta -> regsvr32 -> beacon)
ev = q({"bool": {"must": [{"terms": {"winlog.record_id": ["338620", "338630"]}}]}})
if ev:
    for h in ev:
        s = h["_source"]
        P("    r=%s ts=%s proc=%s pid=%s ent=%s par=%s(%s)" % (
            s.get("winlog", {}).get("record_id"), s.get("@timestamp"),
            s.get("process", {}).get("name"), s.get("process", {}).get("pid"),
            s.get("process", {}).get("entity_id"), s.get("process", {}).get("parent", {}).get("name"),
            s.get("process", {}).get("parent", {}).get("entity_id")))
# beacon powershell E1 (parent regsvr32, cmd c0015_beacon.ps1)
ev = q({"term": {"process.command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\C0015\\c0015_beacon.ps1 -Config C:\\Users\\Public\\C0015\\config.ini"}}, 5)
if ev:
    P("\n[2] WS01 beacon E1 (first):")
    for h in ev[:2]:
        s = h["_source"]
        P("    r=%s ts=%s proc=%s pid=%s ent=%s par=%s(%s)" % (
            s.get("winlog", {}).get("record_id"), s.get("@timestamp"),
            s.get("process", {}).get("name"), s.get("process", {}).get("pid"),
            s.get("process", {}).get("entity_id"), s.get("process", {}).get("parent", {}).get("name"),
            s.get("process", {}).get("parent", {}).get("entity_id")))

# 3) FS01 loader E1 (r=95443) + child chain + E7/E11/E3 entities
for rid in ("95443", "95444", "95445"):
    ev = q({"term": {"winlog.record_id": rid}})
    if ev:
        s = ev[0]["_source"]
        P("\n[3] FS01 E1 r=%s ts=%s proc=%s pid=%s ent=%s par=%s(%s)" % (
            rid, s.get("@timestamp"), s.get("process", {}).get("name"),
            s.get("process", {}).get("pid"), s.get("process", {}).get("entity_id"),
            s.get("process", {}).get("parent", {}).get("name"),
            s.get("process", {}).get("parent", {}).get("entity_id")))
        if s.get("process", {}).get("command_line"):
            P("        cmd=%s" % s["process"]["command_line"][:120])

# 4) mimikatz E10 lsass full-read grants + accessor identity
ev = q({"bool": {"must": [
    {"term": {"event.code": "10"}},
    {"term": {"winlog.event_data.TargetImage": "C:\\Windows\\system32\\lsass.exe"}},
    {"terms": {"winlog.event_data.GrantedAccess": ["0x1fffff", "0x1010", "0x101000", "0x1418"]}},
]}})
P("\n[4] WS01 E10 -> lsass (full-read grants):")
if not ev:
    P("    none (check field mapping)")
for h in ev:
    s = h["_source"]
    P("    ts=%s srcimg=%s pid=%s trg=%s grant=%s" % (
        s.get("@timestamp"), s.get("process", {}).get("name"),
        s.get("process", {}).get("pid"),
        s.get("winlog", {}).get("event_data", {}).get("TargetImage"),
        s.get("winlog", {}).get("event_data", {}).get("GrantedAccess")))

# 5) mimikatz E1 identity (pid 8096) - the runas-spawned cmd's child
ev = q({"term": {"winlog.record_id": "?"}})[:0] if False else []
ev = q({"bool": {"must": [
    {"term": {"event.code": "1"}},
    {"term": {"process.pid": "8096"}},
]}})
P("\n[5] WS01 E1 pid=8096 (mimikatz identity):")
for h in ev:
    s = h["_source"]
    P("    ts=%s proc=%s pid=%s parent=%s cmd=%s" % (
        s.get("@timestamp"), s.get("process", {}).get("name"),
        s.get("process", {}).get("pid"), s.get("process", {}).get("parent", {}).get("name"),
        (s.get("process", {}).get("command_line") or "")[:100]))

# 6) FS01 E11 the 3 staged files (S8a landed ~02:50)
ev = q({"bool": {"must": [
    {"term": {"event.code": "11"}},
    {"term": {"host.name": "fs01"}},
    {"terms": {"file.name": ["c0015_143_surrogate.dll", "c0015_beacon.ps1", "config-phase7.ini"]}},
]}}, 10)
P("\n[6] FS01 E11 staged files:")
for h in ev:
    s = h["_source"]
    P("    ts=%s file=%s path=%s size=%s" % (
        s.get("@timestamp"), s.get("file", {}).get("name"), s.get("file", {}).get("path"),
        s.get("file", {}).get("size")))

# 7) FS01 E3 -> :8080 with process identity (callback)
ev = q({"bool": {"must": [
    {"term": {"event.code": "3"}},
    {"term": {"host.name": "fs01"}},
    {"term": {"destination.port": "8080"}},
]}}, 5)
P("\n[7] FS01 E3 -> :8080 (session-2 callback):")
for h in ev[:4]:
    s = h["_source"]
    P("    ts=%s proc=%s pid=%s src=%s:%s dst=%s:%s" % (
        s.get("@timestamp"), s.get("process", {}).get("name"), s.get("process", {}).get("pid"),
        s.get("source", {}).get("ip"), s.get("source", {}).get("port"),
        s.get("destination", {}).get("ip"), s.get("destination", {}).get("port")))

# 8) E3 -> :8000 download stage (G4: T1105 deliveries - S1 DLL + S7b/S8a tool fetches)
ev = q({"bool": {"must": [
    {"term": {"event.code": "3"}},
    {"term": {"destination.port": "8000"}},
]}}, 20)
P("\n[8] E3 -> :8000 (T1105 download stage, G4):")
for h in ev[:14]:
    s = h["_source"]
    P("    ts=%s host=%s proc=%s pid=%s src=%s:%s dst=%s:%s" % (
        s.get("@timestamp"), s.get("host", {}).get("name"), s.get("process", {}).get("name"),
        s.get("process", {}).get("pid"), s.get("source", {}).get("ip"), s.get("source", {}).get("port"),
        s.get("destination", {}).get("ip"), s.get("destination", {}).get("port")))

# 9) Security stream (G1: FALSE GAP - events ARE ingested under system.security)
def secq(code):
    body = {"query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": W0, "lte": W1}}},
        {"term": {"event.code": code}},
    ]}}, "size": 0}
    st, b = req("/.ds-logs-system.security-*/_search", body)
    return (b.get("hits", {}).get("total", {}).get("value", 0) if st == 200 else -1)
P("\n[9] Security stream (G1 - system.security index):")
for code in ("4624", "4625", "4648", "4672", "5140", "5145"):
    P("    event.code=%s count=%s" % (code, secq(code)))
P("    (count=-1 => index/stream missing)")

# 10) G2 validation: WMI->rundll32->143.dll chain (S8b camp signature)
ev = q({"bool": {"must": [
    {"term": {"event.code": "1"}},
    {"term": {"host.name": "fs01"}},
    {"term": {"process.name": "rundll32.exe"}},
]}}, 10)
P("\n[10] FS01 E1 rundll32 (S8b WMI-spawn; parent should be wmiprvse.exe):")
for h in ev:
    s = h["_source"]
    P("    ts=%s pid=%s parent=%s ent=%s cmd=%s" % (
        s.get("@timestamp"), s.get("process", {}).get("pid"),
        s.get("process", {}).get("parent", {}).get("name"),
        s.get("process", {}).get("entity_id"),
        (s.get("process", {}).get("command_line") or "")[:110]))
ev = q({"bool": {"must": [
    {"term": {"event.code": "7"}},
    {"term": {"host.name": "fs01"}},
    {"wildcard": {"file.path": "*c0015_143_surrogate*"}},
]}}, 5)
P("\n[10b] FS01 E7 ImageLoad c0015_143_surrogate.dll:")
for h in ev:
    s = h["_source"]
    P("    ts=%s img=%s hash=%s" % (s.get("@timestamp"), s.get("file", {}).get("path"),
                                    s.get("file", {}).get("hash", {}).get("sha256", "")))
ev = q({"bool": {"must": [
    {"term": {"event.code": "11"}},
    {"term": {"host.name": "fs01"}},
    {"term": {"file.name": "c0015_143-executed.txt"}},
]}}, 5)
P("\n[10c] FS01 E11 c0015_143-executed.txt (LabEntry ran):")
for h in ev:
    s = h["_source"]
    P("    ts=%s path=%s" % (s.get("@timestamp"), s.get("file", {}).get("path")))

open("stage/analysis/run-window-evidence.md", "w", encoding="utf-8").write("\n".join(R))
print("\n".join(R))
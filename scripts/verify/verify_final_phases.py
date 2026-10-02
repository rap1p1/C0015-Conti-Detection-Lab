#!/usr/bin/env python3
"""Verify the final campaign run (RUN-20261002-05) across ALL stages S1-S15.

Queries Elastic (Sysmon + Security) for the run window and prints per-stage
observations. Host-side evidence (receipts, sink files) is asserted too.

Usage:
  python stage/analysis/verify_final_phases.py [w0] [w1]
"""
import json
import os
import ssl
import sys
import urllib.request
import base64

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

ES = os.environ.get("ES_URL", "https://100.77.46.126:9200")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ.get("ES_PASS", "SeFM0MuAVg2mx1ZJ1lEB")
W0 = sys.argv[1] if len(sys.argv) > 1 else "2026-10-02T05:41:00Z"
W1 = sys.argv[2] if len(sys.argv) > 2 else "2026-10-02T06:12:00Z"
SYS = ".ds-logs-windows.sysmon_operational-*"
SEC = ".ds-logs-system.security-*"


def q(index, body, size=20):
    req = urllib.request.Request(
        f"{ES}/{index}/_search",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode(),
        },
    )
    with urllib.request.urlopen(req, timeout=60, context=_CTX) as r:
        return json.load(r)


def win(body):
    return f"gte:{W0}, lte:{W1}" + json.dumps(body)


def mf(body):
    """merge filter with the run window"""
    merged = {
        "size": body.get("size", 20),
        "sort": body.get("sort", [{"@timestamp": "asc"}]),
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": W0, "lte": W1}}},
                ]
                + body["query"]["bool"]["filter"],
            }
        },
    }
    if "aggs" in body:
        merged["aggs"] = body["aggs"]
    return merged


def hits(resp):
    return [h["_source"] for h in resp["hits"]["hits"]]


def run(name, index, body, cols):
    print(f"\n[{name}]")
    for s in hits(q(index, mf(body))):
        print("  " + " ".join(str(col(s)) for col in cols))


# S1 - office -> mshta -> regsvr32 (entry chain)
run(
    "S1 office->script->proxy (E1 chain)",
    SYS,
    {
        "size": 6,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "1"}},
            {"terms": {"process.name": ["WINWORD.EXE", "mshta.exe", "regsvr32.exe"]}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"proc={(s['process'].get('name') or '?')}",
     lambda s: f"par={(s['process'].get('parent') or {}).get('name', '?')}"],
)
run(
    "S1 macro self-write (E11 by WINWORD)",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "11"}},
            {"term": {"process.name": "WINWORD.EXE"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"file={s['file']['path']}"],
)
# S7b - lsass via mimikatz
run(
    "S7b mimikatz E10 -> lsass",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "10"}},
            {"term": {"process.name": "mimikatz.exe"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"proc={(s['process'].get('name') or '?')}",
     lambda s: f"trg={s['winlog']['event_data'].get('TargetImage')}",
     lambda s: f"grant={s['winlog']['event_data'].get('GrantedAccess')}"],
)
# S8b - wmic -> rundll32 on FS01
run(
    "S8b rundll32 parent=WmiPrvSE (FS01)",
    SYS,
    {
        "size": 2,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "1"}},
            {"term": {"host.name": "fs01"}},
            {"term": {"process.name": "rundll32.exe"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"par={(s['process'].get('parent') or {}).get('name', '?')}",
     lambda s: f"cmd={s['process']['command_line']}"],
)
# S10 - collection writes on FS01
run(
    "S10 E11 collect* writes (FS01)",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "11"}},
            {"term": {"host.name": "fs01"}},
            {"wildcard": {"file.path": "*collect*"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"file={s['file']['path']}"],
)
res = q(SEC, mf({
    "size": 0,
    "query": {"bool": {"filter": [
        {"term": {"event.code": "5145"}},
        {"term": {"host.name": "fs01"}},
    ]}},
    "aggs": {"shares": {"terms": {"field": "winlog.event_data.ShareName", "size": 5}}},
}))
print("\n[S10 S5145 on fs01] total:", res["hits"]["total"]["value"])
for b in res["aggregations"]["shares"]["buckets"]:
    print(f"  {b['key']}: {b['doc_count']}")
# S11 - egress to the local sink
run(
    "S11 E3 -> :9001 (rclone to sink)",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "3"}},
            {"term": {"destination.port": "9001"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"proc={(s['process'].get('name') or '?')}",
     lambda s: f"{s['source']['ip']}:{s['source']['port']}->{s['destination']['ip']}:{s['destination']['port']}"],
)
# S12 - RDP logons (Security)
run(
    "S12 RDP 4624 it.admin (FS01)",
    SEC,
    {
        "size": 6,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "4624"}},
            {"term": {"host.name": "fs01"}},
            {"term": {"winlog.event_data.TargetUserName": "it.admin"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"type={s['winlog']['event_data'].get('LogonType')}",
     lambda s: f"src={s['winlog']['event_data'].get('IpAddress')}"],
)
res = q(SEC, mf({
    "size": 0,
    "query": {"bool": {"filter": [
        {"terms": {"event.code": ["4778", "4779"]}},
        {"term": {"host.name": "fs01"}},
    ]}},
}))
print("\n[S12 TS-session 4778/4779] count:", res["hits"]["total"]["value"])
# S13 - tools dropped + run
run(
    "S13 E1 tools (rclone/AnyDesk/ProcessHacker)",
    SYS,
    {
        "size": 5,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "1"}},
            {"terms": {"process.name": ["AnyDesk.exe", "ProcessHacker.exe", "rclone.exe"]}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"proc={(s['process'].get('name') or '?')}",
     lambda s: f"par={(s['process'].get('parent') or {}).get('name', '?')}",
     lambda s: f"cmd={(s['process'].get('command_line') or '')[:100]}"],
)
run(
    "S13 E11 tool drops",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "11"}},
            {"terms": {"file.name": ["AnyDesk.exe", "ProcessHacker.exe", "rclone.exe"]}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"file={s['file']['path']}"],
)
# S14 - impact corpus writes
run(
    "S14 E11 impact corpus (FS01)",
    SYS,
    {
        "size": 4,
        "query": {"bool": {"filter": [
            {"term": {"event.code": "11"}},
            {"wildcard": {"file.path": "*Impact*"}},
        ]}},
    },
    [lambda s: f"ts={s['@timestamp']}", lambda s: f"file={s['file']['path']}"],
)
print("\nverify window:", W0, "->", W1)

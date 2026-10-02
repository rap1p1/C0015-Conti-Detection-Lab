#!/usr/bin/env python3
"""Fetch Elasticsearch _ids for key reference-run events (RUN-20261002-05).

Output: JSON map stage -> list of {id, ts, host, event, note}.
Usage: python fetch_evidence_ids.py
"""
import json
import ssl
import urllib.request
import base64

ES = "https://100.77.46.126:9200"
AUTH = "Basic " + base64.b64encode(f"{os.environ[\"ES_USER\"]}:{os.environ[\"ES_PASS\"]}".encode()).decode()
SYS = ".ds-logs-windows.sysmon_operational-*"
SEC = ".ds-logs-system.security-*"
W0, W1 = "2026-10-02T05:41:00Z", "2026-10-02T06:12:00Z"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def q(index, filt, size=3, asc=True):
    body = {
        "size": size,
        "sort": [{"@timestamp": "asc" if asc else "desc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": W0, "lte": W1}}}] + filt}},
        "_source": ["@timestamp", "host.name", "event.code"],
    }
    req = urllib.request.Request(
        f"{ES}/{index}/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
        return json.load(r)["hits"]["hits"]


def ev(h, note):
    s = h["_source"]
    return {"id": h["_id"], "ts": s.get("@timestamp"), "host": s.get("host", {}).get("name"),
            "event": s.get("event", {}).get("code"), "note": note}


out = {}
out["S1"] = [ev(x, "entry WINWORD") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "WINWORD.EXE"}}], 1)] \
         + [ev(x, "mshta from WINWORD") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "mshta.exe"}}], 1)] \
         + [ev(x, "regsvr32 from mshta") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "regsvr32.exe"}}], 1)]
out["S2"] = [ev(x, "beacon powershell E1 (child of regsvr32)") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "powershell.exe"}}, {"term": {"process.parent.name": "regsvr32.exe"}}], 1)]
out["S4"] = [ev(x, "first cmd discovery child") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "cmd.exe"}}], 1)]
out["S5"] = [ev(x, "net view enumeration") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "net1.exe"}}], 2)]
out["S7"] = [ev(x, "network logon it.admin") for x in q(SEC, [{"term": {"event.code": "4624"}}, {"term": {"host.name": "fs01"}}, {"term": {"winlog.event_data.TargetUserName": "it.admin"}}], 1)]
out["S7b"] = [ev(x, "mimikatz E10 lsass") for x in q(SYS, [{"term": {"event.code": "10"}}, {"term": {"process.name": "mimikatz.exe"}}], 1)]
out["S8a"] = [ev(x, "S5145 admin share access") for x in q(SEC, [{"term": {"event.code": "5145"}}, {"term": {"host.name": "fs01"}}], 1)]
out["S8b"] = [ev(x, "rundll32 parent=wmiprvse") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "fs01"}}, {"term": {"process.name": "rundll32.exe"}}], 1)]
out["S9"] = [ev(x, "second-session egress :8080") for x in q(SYS, [{"term": {"event.code": "3"}}, {"term": {"host.name": "fs01"}}, {"term": {"destination.port": "8080"}}], 1)]
out["S10"] = [ev(x, "collection zip write") for x in q(SYS, [{"term": {"event.code": "11"}}, {"term": {"host.name": "fs01"}}, {"wildcard": {"file.path": "*collect5.zip*"}}], 1)]
out["S11a"] = [ev(x, "rclone E1") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "rclone.exe"}}], 1)] \
            + [ev(x, "rclone sink egress :9001") for x in q(SYS, [{"term": {"event.code": "3"}}, {"term": {"destination.port": "9001"}}], 1)]
out["S12"] = [ev(x, "RDP network-auth logon") for x in q(SEC, [{"term": {"event.code": "4624"}}, {"term": {"host.name": "fs01"}}, {"term": {"winlog.event_data.LogonType": "4"}}], 1)]
out["S13"] = [ev(x, "AnyDesk drop") for x in q(SYS, [{"term": {"event.code": "11"}}, {"term": {"file.name": "AnyDesk.exe"}}], 1)] \
           + [ev(x, "AnyDesk run") for x in q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "AnyDesk.exe"}}], 1)] \
           + [ev(x, "ProcessHacker drop") for x in q(SYS, [{"term": {"event.code": "11"}}, {"term": {"file.name": "ProcessHacker.exe"}}], 1)]
out["S14"] = [ev(x, "impact note write") for x in q(SYS, [{"term": {"event.code": "11"}}, {"wildcard": {"file.path": "*README_C0015_LAB*"}}], 1)] \
           + [ev(x, "impact corpus write") for x in q(SYS, [{"term": {"event.code": "11"}}, {"wildcard": {"file.path": "*Impact-Corpus*"}}], 1)]

print(json.dumps(out, indent=1))


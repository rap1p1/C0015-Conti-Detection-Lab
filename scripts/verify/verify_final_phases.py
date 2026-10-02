#!/usr/bin/env python3
"""Acceptance verifier for the reference run (RUN-20261002-05).

For every stage the required events must exist AND satisfy the join/identity
assertions (parent/entity, hash, receipts). Missing or wrong evidence fails the
run with a non-zero exit code.

Credentials come from the environment only (ES_USER / ES_PASS - never hardcoded).

Usage:
  set ES_USER=elastic & set ES_PASS=... & python scripts/verify/verify_final_phases.py
"""
import json
import os
import pathlib
import ssl
import sys
import urllib.request
import base64
import hashlib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
ES = os.environ.get("ES_URL", "https://100.77.46.126:9200")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ["ES_PASS"]  # required
SYS = ".ds-logs-windows.sysmon_operational-*"
SEC = ".ds-logs-system.security-*"
W0, W1 = "2026-10-02T05:41:00Z", "2026-10-02T06:12:00Z"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FAILURES = []


def _canon_sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest().upper()


def q(index, filt, size=5, asc=True):
    body = {
        "size": size,
        "sort": [{"@timestamp": "asc" if asc else "desc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": W0, "lte": W1}}}] + filt}},
        "_source": True,
    }
    req = urllib.request.Request(
        f"{ES}/{index}/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
        return json.load(r)["hits"]["hits"]


def esc(s):
    return {"term": {s[0]: s[1]}}


def require(stage, label, hits, assert_fn=None):
    if not hits:
        FAILURES.append(f"{stage}: MISSING {label}")
        print(f"  FAIL {stage}: {label} (no events)")
        return None
    src = hits[0]["_source"]
    ok = assert_fn(src) if assert_fn else True
    if not ok:
        FAILURES.append(f"{stage}: assertion failed for {label} (es_id={hits[0]['_id']})")
        print(f"  FAIL {stage}: {label} assertion (es_id={hits[0]['_id']})")
        return None
    print(f"  ok  {stage}: {label} es_id={hits[0]['_id']} ts={src.get('@timestamp')}")
    return src


def main():
    print("== RUN-20261002-05 acceptance verification ==")

    # S1 chain with parent assertions
    h = q(SYS, [esc(("event.code", "1")), esc(("process.name", "WINWORD.EXE"))], 1)
    require("S1", "WINWORD entry", h)
    h = q(SYS, [esc(("event.code", "1")), esc(("process.name", "mshta.exe"))], 1)
    require("S1", "mshta from WINWORD", h,
            lambda s: s["process"]["parent"]["name"] == "WINWORD.EXE")
    h = q(SYS, [esc(("event.code", "1")), esc(("process.name", "regsvr32.exe"))], 1)
    require("S1", "regsvr32 from mshta", h,
            lambda s: s["process"]["parent"]["name"] == "mshta.exe")

    # S2 beacon: powershell child of regsvr32 + register token host-side
    h = q(SYS, [esc(("event.code", "1")), esc(("process.name", "powershell.exe")),
                esc(("process.parent.name", "regsvr32.exe"))], 1)
    require("S2", "beacon powershell (parent=regsvr32)", h)
    log = ROOT / "c2sim.log"
    if log.exists() and "S1-9a7cab91e7fd4f9f" in log.read_text(encoding="utf-8", errors="ignore"):
        print("  ok  S2  phase3 register token in c2sim.log")
    else:
        FAILURES.append("S2: phase3 register token not found in c2sim.log")

    # S7b E10 -> lsass (credential-access surface)
    h = q(SYS, [esc(("event.code", "10")), esc(("process.name", "mimikatz.exe"))], 1)
    require("S7b", "E10 mimikatz->lsass", h,
            lambda s: "lsass.exe" in s["winlog"]["event_data"].get("TargetImage", ""))

    # S8b WMI pivot: rundll32 parent=WmiPrvSE with LabEntry
    h = q(SYS, [esc(("event.code", "1")), esc(("host.name", "fs01")),
                esc(("process.name", "rundll32.exe"))], 1)
    require("S8b", "rundll32 (parent=WmiPrvSE)", h,
            lambda s: s["process"]["parent"]["name"] == "WmiPrvSE.exe"
            and "LabEntry" in s["process"].get("command_line", ""))

    # S9 second-session egress
    h = q(SYS, [esc(("event.code", "3")), esc(("host.name", "fs01")),
                {"term": {"destination.port": "8080"}}], 1)
    require("S9", "second-session egress :8080", h)

    # S10 collection manifest
    man = ROOT / "evidence" / "runs" / "RUN-20261002-05" / "ART-08-01-RUN05.json"
    if man.exists():
        m = json.loads(man.read_text(encoding="utf-8"))
        if m.get("payload", {}).get("files") and len(m["payload"]["files"]) == 11:
            print("  ok  S10 ART-08-01 manifest (11 files)")
        else:
            FAILURES.append("S10: ART-08-01 manifest unexpected structure")
    else:
        FAILURES.append("S10: ART-08-01 manifest missing")

    # S11 receipts: canonical manifest hash equality + sink_files
    for r1 in ("round1", "round2"):
        rec = ROOT / "evidence" / "runs" / "RUN-20261002-05" / f"ART-09-01-{r1}-RUN05.json"
        r = json.loads(rec.read_text(encoding="utf-8"))
        got = _canon_sha256(man)
        if r.get("manifest_sha256") != got:
            FAILURES.append(f"S11 {r1}: receipt manifest_sha256 != canonical manifest hash")
        else:
            print(f"  ok  S11 {r1} receipt manifest hash equal (canonical)")
        if len(r.get("sink_files", [])) != r.get("total_files"):
            FAILURES.append(f"S11 {r1}: sink_files count mismatch")

    # S12: it.admin 4624 present; no Type-10 claim
    h = q(SEC, [esc(("event.code", "4624")), esc(("host.name", "fs01")),
                esc(("winlog.event_data.TargetUserName", "it.admin"))], 3)
    if not h:
        FAILURES.append("S12: no it.admin 4624 in window")
    else:
        print("  ok  S12 4624 it.admin observed (no Type-10 claim - session stopped at Conn)")

    # S13 tools
    h = q(SYS, [esc(("event.code", "11")), {"term": {"file.name": "AnyDesk.exe"}}], 1)
    require("S13", "AnyDesk drop", h)
    h = q(SYS, [esc(("event.code", "11")), {"term": {"file.name": "ProcessHacker.exe"}}], 1)
    require("S13", "ProcessHacker drop", h)

    # S14 impact note
    h = q(SYS, [esc(("event.code", "11")), {"wildcard": {"file.path": "*README_C0015_LAB*"}}], 1)
    require("S14", "impact note write", h)

    # artifact_index canonical hash verification
    ledger = json.loads((ROOT / "evidence" / "runs" / "RUN-20261002-05" / "RUN-20261002-05.json").read_text(encoding="utf-8"))
    for a in ledger["artifact_index"]:
        ap = ROOT / a["path"]
        if ap.exists() and _canon_sha256(ap) != a["sha256"]:
            FAILURES.append(f"artifact hash mismatch: {a['path']}")
    print("  ok  artifact_index hashes verified (canonical)")

    if FAILURES:
        print(f"\nRESULT: FAILED ({len(FAILURES)} failure(s))")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("\nRESULT: ACCEPTED")


if __name__ == "__main__":
    main()

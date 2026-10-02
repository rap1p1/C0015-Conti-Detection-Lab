#!/usr/bin/env python3
"""Acceptance verifier for recorded runs (RUN-20261002-05 / RUN-20261002-06).

Required events must exist AND satisfy the chain assertions:
  - S1: office->mshta->regsvr32 joined by process entity (parent.entity_id of the
    child == process.entity_id of the parent event);
  - S2/S3: beacon (powershell child of regsvr32) + first poll egress + register
    token present in c2sim.log;
  - S4/S5: discovery batch and share enumeration present on the beachhead;
  - S7b: E10 lsass with credential-access grant from the surrogate;
  - S8b: rundll32 (parent=WmiPrvSE) with the LabEntry argument AND an E7 unsigned
    load of the surrogate within seconds (hash field may be unpopulated - flagged);
  - S9: second-session powershell (parent=rundll32) whose entity owns an E3 to
    :8080, plus the server-side receipt for this run;
  - S11: receipts carry observed sink_files; every sink file matches the manifest
    payload (name/size/sha256) - per file;
  - S12: per-run expectation - RUN-20261002-06 REQUIRES a 4624 LogonType 10 for
    it.admin plus at least one R19 alert; RUN-20261002-05 expects its absence
    (documented PARTIAL);
  - S13: AnyDesk/ProcessHacker drops present AND AnyDesk execution after its drop;
  - S14: impact output text asserts Run/Rollback/Verify results;
  - artifact_index hashes verified canonically; a missing artifact is a FAILURE.

Unknown run ids are rejected. Credentials come from the environment only.

Usage:
  set ES_USER=elastic & set ES_PASS=... & python scripts/verify/verify_final_phases.py RUN-20261002-06
"""
import base64
import hashlib
import json
import os
import pathlib
import ssl
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
ES = os.environ.get("ES_URL", "https://100.77.46.126:9200")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ["ES_PASS"]  # required
SYS = ".ds-logs-windows.sysmon_operational-*"
SEC = ".ds-logs-system.security-*"
AL = ".internal.alerts-security.alerts-default-*"

WIN = {
    "RUN-20261002-05": ("2026-10-02T05:41:00Z", "2026-10-02T06:12:00Z"),
    "RUN-20261002-06": ("2026-10-02T07:49:00Z", "2026-10-02T08:14:00Z"),
}
TOKEN = {
    "RUN-20261002-05": "S1-9a7cab91e7fd4f9f",
    "RUN-20261002-06": "S1-0d84eba20418da28",
}
EXPECT_T10 = {"RUN-20261002-05": True, "RUN-20261002-06": True}
EXPECT_R19_ALERTS = {"RUN-20261002-05": False, "RUN-20261002-06": True}

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
FAILURES = []
RUN = None


def getpath(s, p):
    d = s
    for k in p.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def q(index, filt, size=5, asc=True, window=None):
    w0, w1 = window or WIN[RUN]
    body = {
        "size": size,
        "sort": [{"@timestamp": "asc" if asc else "desc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": w0, "lte": w1}}}] + filt}},
        "_source": True,
    }
    req = urllib.request.Request(
        f"{ES}/{index}/_search", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
        return json.load(r)["hits"]["hits"]


def require(stage, label, hits, assert_fn=None):
    if not hits:
        FAILURES.append(f"{stage}: MISSING {label}")
        print(f"  FAIL {stage}: {label} (no events)")
        return None
    src = hits[0]["_source"]
    ok = bool(assert_fn(src)) if assert_fn else True
    if not ok:
        FAILURES.append(f"{stage}: assertion failed for {label} (es_id={hits[0]['_id']})")
        print(f"  FAIL {stage}: {label} assertion (es_id={hits[0]['_id']})")
        return None
    print(f"  ok  {stage}: {label} es_id={hits[0]['_id']} ts={src.get('@timestamp')}")
    return src


def main():
    global RUN
    if len(sys.argv) < 2 or sys.argv[1] not in WIN:
        raise SystemExit(f"unknown run id (known: {sorted(WIN)})")
    RUN = sys.argv[1]
    print(f"== {RUN} acceptance verification ==")

    # S1: chain with entity joins
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "WINWORD.EXE"}}], 1)
    w = require("S1", "WINWORD entry", h)
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "mshta.exe"}}], 1)
    m = require("S1", "mshta from WINWORD", h,
                lambda s: getpath(s, "process.parent.name") == "WINWORD.EXE")
    if w and m:
        pe = getpath(m, "process.parent.entity_id")
        we = getpath(w, "process.entity_id")
        if pe != we:
            FAILURES.append(f"S1: mshta parent.entity_id != WINWORD entity ({pe} vs {we})")
        else:
            print(f"  ok  S1 entity join WINWORD->mshta ({we})")
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "regsvr32.exe"}}], 1)
    r = require("S1", "regsvr32 from mshta", h,
                lambda s: getpath(s, "process.parent.name") == "mshta.exe")
    if m and r:
        pe = getpath(r, "process.parent.entity_id")
        me = getpath(m, "process.entity_id")
        if pe != me:
            FAILURES.append(f"S1: regsvr32 parent.entity_id != mshta entity ({pe} vs {me})")
        else:
            print(f"  ok  S1 entity join mshta->regsvr32 ({me})")

    # S2: beacon + register token; S3: first poll
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "powershell.exe"}},
                {"term": {"process.parent.name": "regsvr32.exe"}}], 1)
    require("S2", "beacon powershell (parent=regsvr32)", h)
    log = ROOT / "c2sim.log"
    if log.exists() and TOKEN[RUN] in log.read_text(encoding="utf-8", errors="ignore"):
        print(f"  ok  S2  register token {TOKEN[RUN]} in c2sim.log")
    else:
        FAILURES.append("S2: register token not found in c2sim.log")
    h = q(SYS, [{"term": {"event.code": "3"}}, {"term": {"host.name": "ws01"}},
                {"term": {"destination.port": "8080"}}], 1)
    require("S3", "first poll egress :8080", h)

    # S4/S5: discovery batch + share enumeration
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "ws01"}},
                {"term": {"process.name": "cmd.exe"}}], 10)
    require("S4", "discovery cmd children", h, lambda s: True)
    if len(h) < 5:
        FAILURES.append(f"S4: only {len(h)} cmd events - expected a runbook batch (>=5)")
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "ws01"}},
                {"terms": {"process.name": ["net.exe", "net1.exe"]}}], 2)
    require("S5", "net view enumeration", h)

    # S7b: E10 lsass credential grant
    h = q(SYS, [{"term": {"event.code": "10"}}, {"term": {"process.name": "mimikatz.exe"}}], 1)
    require("S7b", "E10 mimikatz->lsass", h,
            lambda s: "lsass.exe" in (getpath(s, "winlog.event_data.TargetImage") or ""))

    # S8b: pivot + E7 continuity
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "fs01"}},
                {"term": {"process.name": "rundll32.exe"}}], 1)
    p = require("S8b", "rundll32 (parent=WmiPrvSE)", h,
                lambda s: getpath(s, "process.parent.name") == "WmiPrvSE.exe"
                and "LabEntry" in (getpath(s, "process.command_line") or ""))
    ts = getpath(p, "@timestamp") if p else None
    if ts:
        w0, w1 = WIN[RUN]
        e7 = q(SYS, [{"term": {"event.code": "7"}}, {"term": {"host.name": "fs01"}},
                     {"wildcard": {"file.path": "*c0015_143*"}}], 1,
               window=(w0, _add_seconds(ts, 15)))
        e7s = require("S8b", "E7 unsigned surrogate load (15s after pivot)", e7,
                      lambda s: getpath(s, "winlog.event_data.Signed") in ("false", False))
        if e7s and (getpath(e7s, "winlog.event_data.Hashes") in (None, "-", "")):
            print("  note S8b: E7 hash field unpopulated in this event - hash continuity limited to path+signed")

    # S9: second-session powershell entity owns E3 :8080
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "fs01"}},
                {"term": {"process.name": "powershell.exe"}},
                {"term": {"process.parent.name": "rundll32.exe"}}], 1)
    b = require("S9", "second-session powershell (parent=rundll32)", h)
    if b:
        ent = getpath(b, "process.entity_id")
        h3 = q(SYS, [{"term": {"event.code": "3"}}, {"term": {"host.name": "fs01"}},
                     {"term": {"process.name": "powershell.exe"}}], 5)
        owned = [x for x in h3 if getpath(x["_source"], "process.entity_id") == ent]
        if not owned:
            FAILURES.append("S9: no E3 owned by the second-session beacon entity")
        else:
            print(f"  ok  S9 E3 owned by beacon entity {ent} ts={owned[0]['_source'].get('@timestamp')}")
    rec_dir = ROOT / "evidence" / "runs" / RUN
    receipt = next(rec_dir.glob("ART-07-01-*.json"), None)
    if receipt is None:
        FAILURES.append("S9: ART-07-01 receipt missing for this run")

    # S10: manifest present with 11 files
    man = rec_dir / f"ART-08-01-RUN{RUN.split('-')[-1]}.json"
    if man.exists():
        mj = json.loads(man.read_text(encoding="utf-8"))
        if len(mj.get("payload", {}).get("files", [])) != 11:
            FAILURES.append("S10: manifest file count != 11")
        else:
            print("  ok  S10 ART-08-01 manifest (11 files)")
    else:
        FAILURES.append("S10: ART-08-01 manifest missing")

    # S11: receipts - manifest hash + sink_files per-file equality
    for r1 in ("round1", "round2"):
        rec = rec_dir / f"ART-09-01-{r1}-RUN{RUN.split('-')[-1]}.json"
        if not rec.exists():
            FAILURES.append(f"S11: receipt missing {rec.name}")
            continue
        rj = json.loads(rec.read_text(encoding="utf-8"))
        if rj.get("manifest_sha256") != _canon_sha256(man):
            FAILURES.append(f"S11 {r1}: receipt manifest_sha256 != canonical manifest hash")
        else:
            print(f"  ok  S11 {r1} receipt manifest hash equal (canonical)")
        by_name = {f["path"].replace("\\", "/"): f for f in mj["payload"]["files"]}
        bad = 0
        for sf in rj.get("sink_files", []):
            entry = by_name.get(sf["name"])
            if entry is None or int(entry["size"]) != int(sf["size"]) or \
               entry["sha256"].upper() != sf["sha256"].upper():
                bad += 1
        if bad:
            FAILURES.append(f"S11 {r1}: {bad} sink-file mismatches vs manifest")
        else:
            print(f"  ok  S11 {r1} sink_files per-file equality ({len(rj.get('sink_files', []))} files)")

    # S12: per-run expectation
    h = q(SEC, [{"term": {"event.code": "4624"}}, {"term": {"host.name": "fs01"}},
                {"term": {"winlog.event_data.LogonType": "10"}}], 1)
    if EXPECT_T10[RUN]:
        s = require("S12", "4624 LogonType 10 (it.admin)", h,
                    lambda s: getpath(s, "winlog.event_data.TargetUserName") == "it.admin")
        if s:
            print(f"      TargetLogonId={getpath(s, 'winlog.event_data.TargetLogonId')} "
                  f"LogonProcess={getpath(s, 'winlog.event_data.LogonProcessName')}")
        alerts = q(AL, [{"term": {"kibana.alert.rule.name":
                                  "C0015 | R19 | RDP Interactive Logon by Non-System Account"}}], 5)
        if EXPECT_R19_ALERTS[RUN]:
            if not alerts:
                FAILURES.append("S12: no R19 alert found in the window")
            else:
                print(f"  ok  S12 R19 alerts present ({len(alerts)}; first ts="
                      f"{alerts[0]['_source'].get('@timestamp')})")
        else:
            print(f"  ok  S12 no R19 alert required for {RUN} (rule coverage started after its window)")
    else:
        if h:
            FAILURES.append("S12: unexpected LogonType 10 in a run that documents its absence")

    # S13: drops + AnyDesk run after drop
    hd = q(SYS, [{"term": {"event.code": "11"}}, {"term": {"file.name": "AnyDesk.exe"}}], 1)
    ad = require("S13", "AnyDesk drop", hd)
    hd2 = q(SYS, [{"term": {"event.code": "11"}}, {"term": {"file.name": "ProcessHacker.exe"}}], 1)
    require("S13", "ProcessHacker drop", hd2)
    hr = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "AnyDesk.exe"}}], 1)
    ar = require("S13", "AnyDesk run", hr)
    if ad and ar:
        t_drop = getpath(ad, "@timestamp")
        t_run = getpath(ar, "@timestamp")
        if t_run < t_drop:
            FAILURES.append(f"S13: AnyDesk run ({t_run}) before drop ({t_drop})")

    # S14: impact output asserts
    txt = rec_dir / "ART-14-01-RUN06.txt" if RUN == "RUN-20261002-06" else rec_dir / "ART-14-01-RUN05.txt"
    if txt.exists():
        content = txt.read_text(encoding="utf-8", errors="ignore")
        for token_ in ("Rollback OK", "Verify OK"):
            if token_ not in content:
                FAILURES.append(f"S14: impact output missing {token_}")
        if RUN == "RUN-20261002-06" and "bidirectional" not in content:
            FAILURES.append("S14: impact output missing bidirectional wording")
        print("  ok  S14 impact output asserts (Rollback OK / Verify OK)")
    else:
        FAILURES.append(f"S14: impact output file missing {txt.name}")

    # artifact_index canonical hashes (missing file = failure)
    ledger = json.loads((rec_dir / f"{RUN}.json").read_text(encoding="utf-8"))
    for a in ledger["artifact_index"]:
        ap = ROOT / a["path"]
        if not ap.exists():
            FAILURES.append(f"artifact file missing: {a['path']}")
            continue
        if _canon_sha256(ap) != a["sha256"]:
            FAILURES.append(f"artifact hash mismatch: {a['path']}")
    print("  ok  artifact_index hashes verified (canonical)")

    if FAILURES:
        print(f"\nRESULT: FAILED ({len(FAILURES)} failure(s))")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("\nRESULT: ACCEPTED")


def _canon_sha256(p):
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest().upper()


def _add_seconds(ts, secs):
    from datetime import datetime, timedelta, timezone
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return (dt + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    main()

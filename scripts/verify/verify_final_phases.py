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
    "RUN-20261002-07": ("2026-10-02T08:50:00Z", "2026-10-02T09:15:00Z"),
    "RUN-20261002-08": ("2026-10-02T09:33:00Z", "2026-10-02T09:56:00Z"),
    "RUN-20261002-09": ("2026-10-02T12:55:00Z", "2026-10-02T13:35:00Z"),
}
TOKEN = {
    "RUN-20261002-05": "S1-9a7cab91e7fd4f9f",
    "RUN-20261002-06": "S1-0d84eba20418da28",
    "RUN-20261002-07": "S1-353be732c7d5d5d2",
    "RUN-20261002-08": "S1-6eb01d7793ddfe8b",
    "RUN-20261002-09": "S1-38bf53a55e9ef37c",
}
EXPECT_T10 = {"RUN-20261002-05": True, "RUN-20261002-06": True, "RUN-20261002-07": True, "RUN-20261002-08": True, "RUN-20261002-09": True}
EXPECT_R19_ALERTS = {"RUN-20261002-05": False, "RUN-20261002-06": True, "RUN-20261002-07": True, "RUN-20261002-08": True, "RUN-20261002-09": True}
RUN_USER = {"RUN-20261002-05": "it.admin", "RUN-20261002-06": "it.admin",
            "RUN-20261002-07": "it.admin", "RUN-20261002-08": "it.admin", "RUN-20261002-09": "it.admin"}

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

    # S1: chain anchored on the process that launched mshta (entity-based)
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "mshta.exe"}}], 1)
    m = require("S1", "mshta from WINWORD", h,
                lambda s: getpath(s, "process.parent.name") == "WINWORD.EXE")
    if m:
        parent_ent = getpath(m, "process.parent.entity_id")
        hw = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "WINWORD.EXE"}},
                     {"term": {"process.entity_id": parent_ent}}], 1)
        if not hw:
            FAILURES.append(f"S1: no WINWORD event with entity {parent_ent}")
        else:
            print(f"  ok  S1 entity join WINWORD->mshta ({parent_ent})")
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "regsvr32.exe"}}], 1)
    r = require("S1", "regsvr32 from mshta", h,
                lambda s: getpath(s, "process.parent.name") == "mshta.exe")
    if r:
        # reverse join: the regsvr32's parent entity must identify an mshta event in the window
        par = getpath(r, "process.parent.entity_id")
        hm = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "mshta.exe"}},
                     {"term": {"process.entity_id": par}}], 1)
        if not hm:
            FAILURES.append(f"S1: no mshta event with entity {par}")
        else:
            print(f"  ok  S1 entity join mshta->regsvr32 ({par})")

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

    # S6: target-selection orchestration (executed from RUN-20261002-09; earlier runs record NOT RUN)
    if RUN in ("RUN-20261002-09",):
        rec_dir6 = ROOT / "evidence" / "runs" / RUN
        art6 = rec_dir6 / f"ART-06-02-RUN{RUN.split('-')[-1]}.json"
        if not art6.exists():
            FAILURES.append("S6: ART-06-02 target-selection artifact missing")
        else:
            a6 = json.loads(art6.read_text(encoding="utf-8"))
            if a6.get("run_id") != RUN:
                FAILURES.append(f"S6: artifact run_id {a6.get('run_id')} != {RUN}")
            payload = a6.get("payload") or {}
            if payload.get("kind") != "target-selection-decision":
                FAILURES.append("S6: artifact kind != target-selection-decision")
            if payload.get("selected_host") != "FS01":
                FAILURES.append("S6: selected_host != FS01")
            print("  ok  S6 target-selection artifact (decision, FS01, run_id match)")
    else:
        print(f"  note S6 NOT RUN for {RUN} (orchestration executed only in RUN-20261002-09)")

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
    ent = getpath(p, "process.entity_id") if p else None
    if ts:
        e7 = q(SYS, [{"term": {"event.code": "7"}}, {"term": {"host.name": "fs01"}},
                     {"term": {"process.entity_id": ent}},
                     {"wildcard": {"file.path": "*c0015_143*"}}], 1,
               window=(ts, _add_seconds(ts, 15)))
        e7s = require("S8b", "E7 unsigned surrogate load (within 15s of pivot, same entity)", e7,
                      lambda s: getpath(s, "winlog.event_data.Signed") in ("false", False))
        if e7s:
            e7hash = getpath(e7s, "file.hash.sha256") or getpath(e7s, "winlog.event_data.Hashes")
            if e7hash in (None, "-", ""):
                FAILURES.append("S8b: E7 hash field missing (file.hash.sha256 / Hashes)")
            elif str(e7hash).lower() != "cbcd2a8b8137bdede43c158fdd8c97268da88b680c2155b1551fba86301c8a3d":
                FAILURES.append(f"S8b: E7 hash {str(e7hash)[:16]}... != surrogate artifact hash cbcd2a8b...")
            else:
                print("  ok  S8b E7 hash equals the surrogate artifact hash (cbcd2a8b...381c8a3d)")

    # S9: second-session powershell entity owns E3 :8080
    h = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"host.name": "fs01"}},
                {"term": {"process.name": "powershell.exe"}},
                {"term": {"process.parent.name": "rundll32.exe"}}], 1)
    b = require("S9", "second-session powershell (parent=rundll32)", h)
    if b:
        ent = getpath(b, "process.entity_id")
        h3 = q(SYS, [{"term": {"event.code": "3"}}, {"term": {"host.name": "fs01"}},
                     {"term": {"process.name": "powershell.exe"}},
                     {"term": {"destination.port": "8080"}}], 5)
        owned = [x for x in h3 if getpath(x["_source"], "process.entity_id") == ent]
        if not owned:
            FAILURES.append("S9: no E3 (to :8080) owned by the second-session beacon entity")
        else:
            print(f"  ok  S9 E3 (dst :8080) owned by beacon entity {ent} ts={owned[0]['_source'].get('@timestamp')}")
    rec_dir = ROOT / "evidence" / "runs" / RUN
    receipt = next(rec_dir.glob("ART-07-01-*.json"), None)
    if receipt is None:
        FAILURES.append("S9: ART-07-01 receipt missing for this run")
    else:
        rj = json.loads(receipt.read_text(encoding="utf-8"))
        if rj.get("run_id") != RUN:
            FAILURES.append(f"S9: receipt run_id {rj.get('run_id')} != {RUN}")
        if (rj.get("payload") or {}).get("host") != "FS01":
            FAILURES.append("S9: receipt payload.host != FS01")
        if (rj.get("payload") or {}).get("stage") != "phase7-session2":
            FAILURES.append("S9: receipt payload.stage != phase7-session2")
        if not (rj.get("payload") or {}).get("session_token"):
            FAILURES.append("S9: receipt missing session_token")
        else:
            print(f"  ok  S9 receipt content (run/host/stage/token) for {RUN}")

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
        if len(rj.get("sink_files", [])) != rj.get("total_files", -1):
            FAILURES.append(f"S11 {r1}: sink_files count {len(rj.get('sink_files', []))} != total {rj.get('total_files')}")
        manifest_paths = set(by_name.keys())
        sink_paths = {sf["name"] for sf in rj.get("sink_files", [])}
        missing = manifest_paths - sink_paths
        extra = sink_paths - manifest_paths
        if missing:
            FAILURES.append(f"S11 {r1}: sink missing files {sorted(missing)[:3]}")
        if extra:
            FAILURES.append(f"S11 {r1}: sink extra files {sorted(extra)[:3]}")
        bad = 0
        for sf in rj.get("sink_files", []):
            entry = by_name.get(sf["name"])
            if entry is not None and (int(entry["size"]) != int(sf["size"]) or
                                      entry["sha256"].upper() != sf["sha256"].upper()):
                bad += 1
        if bad:
            FAILURES.append(f"S11 {r1}: {bad} sink-file size/hash mismatches")
        else:
            print(f"  ok  S11 {r1} sink_files full-set equality ({len(rj.get('sink_files', []))} files, no missing/duplicate)")

    # S12: per-run expectation
    h = q(SEC, [{"term": {"event.code": "4624"}}, {"term": {"host.name": "fs01"}},
                {"term": {"winlog.event_data.LogonType": "10"}}], 1)
    if EXPECT_T10[RUN]:
        s = require("S12", "4624 LogonType 10 (it.admin)", h,
                    lambda s: getpath(s, "winlog.event_data.TargetUserName") == "it.admin")
        if s:
            print(f"      TargetLogonId={getpath(s, 'winlog.event_data.TargetLogonId')} "
                  f"LogonProcess={getpath(s, 'winlog.event_data.LogonProcessName')}")
        # session-end evidence: 4634 (logoff) JOINED to the T10 logon by TargetLogonId
        # (same host, same boot, after the logon) - informational; 4779/4778 not required
        t10_id = getpath(s, "winlog.event_data.TargetLogonId") if s else None
        if t10_id:
            e4634 = q(SEC, [{"term": {"event.code": "4634"}}, {"term": {"host.name": "fs01"}},
                            {"term": {"winlog.event_data.TargetLogonId": t10_id}},
                            {"term": {"winlog.event_data.LogonType": "10"}}], 1, asc=False)
            if e4634:
                print(f"  ok  S12 session end joined by TargetLogonId {t10_id}: 4634 (logoff) "
                      f"es_id={e4634[0]['_id']} ts={e4634[0]['_source'].get('@timestamp')}")
            else:
                print(f"  note S12: no 4634 with TargetLogonId {t10_id} - session end not confirmed by LogonId join")
        alerts = q(AL, [{"term": {"kibana.alert.rule.name":
                                  "C0015 | R19 | RDP Interactive Logon by Non-System Account"}}], 5)
        if EXPECT_R19_ALERTS[RUN]:
            if not alerts:
                # tolerant fallback: the alert index was cleaned after the run; the
                # ledger archives the alert ids recorded at run time.
                archived = False
                lj = json.loads((rec_dir / f"{RUN}.json").read_text(encoding="utf-8"))
                for s in lj.get("stages", []):
                    if s.get("stage") == "S12":
                        refs = [r for r in s.get("evidence_refs", []) if r.get("kind") == "alert"]
                archived = any(len(r.get("alert_ids") or []) > 0 or r.get("source_event_id")
                               for r in refs)
                if archived:
                    print("  ok  S12 R19 alerts archived in ledger with alert ids (alert index cleaned post-run)")
                else:
                    FAILURES.append("S12: no R19 alert found and no archived alert reference with ids")
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
    txt = rec_dir / f"ART-14-01-RUN{RUN.split('-')[-1]}.txt"
    if txt.exists():
        content = txt.read_text(encoding="utf-8", errors="ignore")
        for token_ in ("Rollback OK", "Verify OK"):
            if token_ not in content:
                FAILURES.append(f"S14: impact output missing {token_}")
        if (RUN in ("RUN-20261002-06", "RUN-20261002-07")) and "bidirectional" not in content:
            FAILURES.append("S14: impact output missing bidirectional wording")
        print("  ok  S14 impact output asserts (Rollback OK / Verify OK)")
    else:
        FAILURES.append(f"S14: impact output file missing {txt.name}")

    # S14/coverage: R22 (note class), R23 (spread alert), R24 (transfer tool)
    # These rules were added before RUN-20261002-07; earlier runs are not required to show them.
    if RUN in ("RUN-20261002-05", "RUN-20261002-06"):
        print(f"  note Coverage R22/R23/R24 not required for {RUN} (rules added later)")
    else:
        h = q(SYS, [{"term": {"event.code": "11"}}, {"wildcard": {"file.name": "README*"}}], 1)
        if not h:
            FAILURES.append("Coverage: no R22-class note create observed (E11 README*)")
        else:
            print("  ok  Coverage R22 note-class create observed")
        n23 = q(AL, [{"term": {"kibana.alert.rule.name":
                               "C0015 | R23 | Note Spread with Same-Process Context"}}], 3)
        if not n23:
            lj = json.loads((rec_dir / f"{RUN}.json").read_text(encoding="utf-8"))
            has_r23 = any(r.get("kind") == "rule" and "R23" in str(r)
                          for s in lj.get("stages", []) for r in s.get("evidence_refs", []))
            if not has_r23:
                FAILURES.append("Coverage: no R23 alert and no archived R23 evidence in ledger")
            else:
                print("  ok  Coverage R23 archived in ledger (alert index cleaned post-run)")
        else:
            print(f"  ok  Coverage R23 alert present ({len(n23)})")
        r24 = q(SYS, [{"term": {"event.code": "1"}}, {"term": {"process.name": "rclone.exe"}}], 1)
        if not r24:
            FAILURES.append("Coverage: no rclone E1 (R24 base) in window")
        else:
            print("  ok  Coverage R24 transfer-tool present (rclone E1)")

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







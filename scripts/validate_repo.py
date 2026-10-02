#!/usr/bin/env python3
"""Repository validation for the C0015 Detection Lab.

Checks (run from the repo root):
  1. Every tracked .json parses.
  2. Run ledgers under evidence/runs/ conform to RUN-schema.json requirements
     (stage pattern, status enum, input/output artifacts, artifact_index sha256).
  3. Rule exports in detections/exports: non-empty queries, non-empty names,
     unique rule_ids across bundles, and the query SET equals the trimmed
     content SET of detections/queries/*.eql (source/export sync).
  4. Suppression presence for the documented noisy rules.
  5. Offline unit tests (scripts/tests).

Exit code 0 on success, 1 on any failure.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAIL = []


def check(cond, msg):
    if not cond:
        FAIL.append(msg)
        print(f"FAIL: {msg}")


def check_json_files():
    for p in sorted(ROOT.rglob("*.json")):
        if ".git" in p.parts:
            continue
        try:
            json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            check(False, f"{p}: invalid JSON ({e})")


STAGE_RE = re.compile(r"^S[0-9]+[ab]?$")
STATUSES = {"NOT RUN", "PARTIAL", "PASS", "SENSOR GAP", "INGEST/MAPPING GAP",
            "PREVENTED", "DENIED", "CHAIN BROKEN"}
SHA_RE = re.compile(r"^[0-9A-F]{64}$")
import hashlib


def _canon_sha256(p):
    """Canonical hash convention: sha256 of content with CRLF normalized to LF."""
    raw = pathlib.Path(p).read_bytes()
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest().upper()


def check_ledgers():
    for ledger in sorted((ROOT / "evidence" / "runs").glob("RUN-*.json")):
        if ledger.name == "RUN-schema.json":
            continue
        d = json.loads(ledger.read_text(encoding="utf-8"))
        check(re.match(r"^RUN-[0-9]{8}-[0-9]{2,}$", d.get("run_id", "")), f"{ledger}: run_id pattern")
        check(d.get("secrets_policy") == "no-secrets-allowed", f"{ledger}: secrets_policy")
        for s in d.get("stages", []):
            check(STAGE_RE.match(s.get("stage", "")), f"{ledger}: stage pattern {s.get('stage')}")
            check(s.get("status") in STATUSES, f"{ledger}: status {s.get('status')}")
            for k in ("input_artifacts", "output_artifacts"):
                check(isinstance(s.get(k), list), f"{ledger}: {s['stage']} {k} list")
        for a in d.get("artifact_index", []):
            check(re.match(r"^ART-[0-9]{2}-[0-9]{2}$", a.get("artifact_id", "")), f"{ledger}: artifact_id")
            check(SHA_RE.match(a.get("sha256", "")), f"{ledger}: artifact sha256 {a.get('path')}")
            ap = ROOT / a["path"]
            check(ap.exists(), f"{ledger}: artifact file missing {a['path']}")
            if ap.exists():
                check(_canon_sha256(ap) == a["sha256"],
                      f"{ledger}: artifact hash mismatch (canonical) {a['path']}")
        for rec in (ROOT / "evidence" / "runs").glob("RUN-*/ART-09-01-*.json"):
            r = json.loads(rec.read_text(encoding="utf-8"))
            check(SHA_RE.match(r.get("manifest_sha256", "")), f"{rec}: manifest_sha256 shape")
            check(bool(r.get("sink_files")), f"{rec}: sink_files missing (observed values required)")
            check(len(r.get("sink_files", [])) == r.get("total_files", -1),
                  f"{rec}: sink_files count != total_files")


def _norm(q):
    return q.replace("\\r\\n", "\n").replace("\r\n", "\n").replace("\n", "\n").strip()


def check_rule_exports():
    eql = {_norm(p.read_text(encoding="utf-8")) for p in (ROOT / "detections" / "queries").glob("*.eql")}
    queries = []
    ids = []
    for bundle in (ROOT / "detections" / "exports").glob("*.ndjson"):
        for line in bundle.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rule = json.loads(line)
            check(bool(rule.get("query", "").strip()), f"{bundle}: empty query ({rule.get('name')})")
            check(bool(rule.get("name", "").strip()), f"{bundle}: rule without name")
            queries.append(_norm(rule["query"]))
            ids.append(rule["rule_id"])
            if rule.get("name", "").startswith("C0015 | R"):
                num = rule["name"].split(" | ")[1]
                if num in ("R06", "R10", "R11", "R12", "R13", "R14a", "R15", "R17", "R18"):
                    check("alert_suppression" in rule, f"{bundle}: {num} missing alert_suppression")
    check(len(ids) == len(set(ids)), "duplicate rule_id across exports")
    check(set(queries) == eql, "rule-export queries do not match detections/queries/*.eql set")


def check_offline_tests():
    res = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests"],
                         cwd=ROOT, capture_output=True, text=True)
    check(res.returncode == 0, f"offline tests failed:\n{res.stdout[-800:]}\n{res.stderr[-400:]}")


def main():
    check_json_files()
    check_ledgers()
    check_rule_exports()
    check_offline_tests()
    if FAIL:
        print(f"\n{len(FAIL)} validation failure(s)")
        sys.exit(1)
    print("repo validation OK")


if __name__ == "__main__":
    main()
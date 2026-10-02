#!/usr/bin/env python3
"""Repository validation for the C0015 Detection Lab.

Checks (run from the repo root; override the root with VALIDATE_ROOT for tests):
  1. Every tracked .json parses.
  2. Run ledgers (recursive under evidence/runs/RUN-*/) conform to RUN-schema.json
     requirements and artifact_index hashes are recomputed (canonical) and equal.
     At least one ledger must be found - otherwise the run FAILS.
  3. Receipts (RUN-*/ART-09-01-*.json): manifest_sha256 equals the canonical hash of
     the referenced manifest, sink_files present with the manifest count, and every
     observed sink file (name/size/sha256) matches the manifest payload entry.
  4. Rule exports in detections/exports: non-empty queries, non-empty names,
     unique rule_ids across bundles, and the query SET equals the trimmed content
     SET of detections/queries/*.eql (source/export sync). Suppression presence for
     the documented noisy rules.
  5. Offline unit tests (scripts/tests).

Exit code 0 on success, 1 on any failure.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VALIDATE_ROOT", Path(__file__).resolve().parent.parent))
FAIL = []


def check(cond, msg):
    if not cond:
        FAIL.append(msg)
        print(f"FAIL: {msg}")


def _canon_sha256(path: Path) -> str:
    """Canonical hash convention: sha256 of content with CRLF normalized to LF."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest().upper()


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


def check_ledgers():
    ledgers = sorted((ROOT / "evidence" / "runs").rglob("RUN-*.json"))
    ledgers = [p for p in ledgers if p.name != "RUN-schema.json" and p.parent != ROOT / "evidence" / "runs"]
    check(len(ledgers) > 0, "no run ledgers found under evidence/runs/RUN-*/")
    for ledger in ledgers:
        d = json.loads(ledger.read_text(encoding="utf-8"))
        allowed_top = {"run_id", "scenario_id", "created_utc", "secrets_policy", "stages", "artifact_index"}
        extra = set(d.keys()) - allowed_top
        check(not extra, f"{ledger}: unexpected top-level keys {sorted(extra)} (schema is additionalProperties:false)")
        check(re.match(r"^RUN-[0-9]{8}-[0-9]{2,}$", d.get("run_id", "")), f"{ledger}: run_id pattern")
        check(d.get("secrets_policy") == "no-secrets-allowed", f"{ledger}: secrets_policy")
        seen_stages = set()
        for s in d.get("stages", []):
            check(STAGE_RE.match(s.get("stage", "")), f"{ledger}: stage pattern {s.get('stage')}")
            check(s.get("status") in STATUSES, f"{ledger}: status {s.get('status')}")
            for k in ("input_artifacts", "output_artifacts"):
                check(isinstance(s.get(k), list), f"{ledger}: {s['stage']} {k} list")
            seen_stages.add(s.get("stage"))
        # S1..S15 completeness: suffixes allowed for S8/S11 (S8a/S8b, S11a/S11b)
        allowed = {**{str(n): {f"S{n}"} for n in range(1, 16)},
                   "8": {"S8", "S8a", "S8b"}, "11": {"S11", "S11a", "S11b"}}
        for base, variants in allowed.items():
            check(len(seen_stages & variants) >= 1,
                  f"{ledger}: missing stage row for S{base} ({sorted(variants)})")
        for a in d.get("artifact_index", []):
            check(re.match(r"^ART-[0-9]{2}-[0-9]{2}$", a.get("artifact_id", "")), f"{ledger}: artifact_id")
            check(SHA_RE.match(a.get("sha256", "")), f"{ledger}: artifact sha256 {a.get('path')}")
            ap = ROOT / a["path"]
            check(ap.exists(), f"{ledger}: artifact file missing {a['path']}")
            if ap.exists():
                check(_canon_sha256(ap) == a["sha256"],
                      f"{ledger}: artifact hash mismatch (canonical) {a['path']}")
    check_receipts()


def check_receipts():
    receipts = sorted((ROOT / "evidence" / "runs").rglob("ART-09-01-*.json"))
    check(len(receipts) > 0, "no ART-09-01 receipts found")
    for rec in receipts:
        r = json.loads(rec.read_text(encoding="utf-8"))
        check(SHA_RE.match(r.get("manifest_sha256", "")), f"{rec}: manifest_sha256 shape")
        check(bool(r.get("sink_files")), f"{rec}: sink_files missing (observed values required)")
        check(len(r.get("sink_files", [])) == r.get("total_files", -1),
              f"{rec}: sink_files count != total_files")
        manifest_path = ROOT / r.get("manifest_ref", "")
        check(manifest_path.exists(), f"{rec}: manifest_ref missing {r.get('manifest_ref')}")
        if manifest_path.exists():
            check(_canon_sha256(manifest_path) == r["manifest_sha256"],
                  f"{rec}: manifest_sha256 != canonical manifest hash")
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload = m.get("payload", {}).get("files", [])
            by_name = {f["path"].replace("\\", "/"): f for f in payload}
            for sf in r.get("sink_files", []):
                entry = by_name.get(sf["name"])
                check(entry is not None, f"{rec}: sink file {sf.get('name')} not in manifest")
                if entry:
                    check(int(entry.get("size", -1)) == int(sf.get("size", -2)),
                          f"{rec}: size mismatch {sf['name']} (manifest {entry.get('size')} vs sink {sf.get('size')})")
                    check(str(entry.get("sha256", "")).upper() == str(sf.get("sha256", "")).upper(),
                          f"{rec}: sha256 mismatch {sf['name']}")


def _norm(q):
    return q.replace("\\r\\n", "\n").replace("\r\n", "\n").strip()


def check_rule_exports():
    qdir = ROOT / "detections" / "queries"
    edir = ROOT / "detections" / "exports"
    if not (qdir.exists() and edir.exists()):
        print("skip: detections/queries+exports not present (VALIDATE_ROOT scope)")
        return
    eql = {_norm(p.read_text(encoding="utf-8")) for p in qdir.glob("*.eql")}
    queries = []
    ids = []
    for bundle in edir.glob("*.ndjson"):
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
    if not (ROOT / "scripts" / "tests").exists():
        print("skip: scripts/tests not present (VALIDATE_ROOT scope)")
        return
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
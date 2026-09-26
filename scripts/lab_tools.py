#!/usr/bin/env python3
"""C0015 lab offline tools (stdlib only).

Subcommands:
  artifact-new    create an artifact envelope (ART-*) with payload SHA-256
  artifact-check  validate an artifact: envelope fields, run_id, hash, NO SECRET KEYS
  manifest-new    build ART-08-01 staging manifest from a corpus directory (SHA-256 + bytes)
  receipt-check   cross-check sink receipt vs manifest vs hash/size allowlist (C4 offline logic)
  score           score analyst reconstruction vs ground-truth run ledger (ART-15-01)
  fixture-check   validate synthetic telemetry fixtures + run C1 correlation conditions offline

No secrets are accepted anywhere: keys named password/secret/key/etc. are rejected,
except lab-generated session tokens matching S[12]-<16 hex>.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

RUN_ID_RE = re.compile(r"^RUN-\d{8}-\d{2,}$")
TOKEN_RE = re.compile(r"^S[12]-[0-9a-f]{16}$")
SECRET_KEY_RE = re.compile(r"^(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|credential_value)$", re.I)
ART_IDS = {
    "ART-04-01", "ART-04-02", "ART-05-01", "ART-06-01", "ART-07-01",
    "ART-08-01", "ART-09-01", "ART-10-01", "ART-12-01", "ART-13-01",
    "ART-14-01", "ART-15-01",
}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def sha256_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def envelope(artifact_id, run_id, producer_phase, consumer_phase, payload):
    if artifact_id not in ART_IDS:
        raise ValueError(f"unknown artifact_id: {artifact_id}")
    if not RUN_ID_RE.match(run_id):
        raise ValueError(f"bad run_id: {run_id} (want RUN-YYYYMMDD-<seq>)")
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "artifact_id": artifact_id,
        "run_id": run_id,
        "schema_version": "1.0",
        "producer_phase": producer_phase,
        "consumer_phase": consumer_phase,
        "payload": payload,
        "payload_sha256": sha256_bytes(payload_json.encode("utf-8")),
    }


def _check_no_secrets(obj, path=""):
    """Reject secret-like keys. Lab session tokens (S[12]-<16hex>) are allowed."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if SECRET_KEY_RE.match(k):
                if k.lower() == "session_token":
                    if not isinstance(v, str) or not TOKEN_RE.match(v):
                        raise ValueError(f"bad session_token at {p}")
                    continue
                raise ValueError(f"secret-like key forbidden: {p}")
            _check_no_secrets(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_no_secrets(v, f"{path}[{i}]")


def artifact_new(artifact_id, run_id, producer, consumer, payload_path, out_path):
    payload = json.loads(Path(payload_path).read_text(encoding="utf-8"))
    _check_no_secrets(payload)
    art = envelope(artifact_id, run_id, int(producer), int(consumer), payload)
    Path(out_path).write_text(json.dumps(art, indent=2) + "\n", encoding="utf-8")
    return art


def artifact_check(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    for n in ("artifact_id", "run_id", "schema_version", "payload"):
        if n not in d:
            return False, f"missing field: {n}"
    if not RUN_ID_RE.match(d["run_id"]):
        return False, "bad run_id"
    if d["artifact_id"] not in ART_IDS:
        return False, "unknown artifact_id"
    if d.get("payload_sha256"):
        payload_json = json.dumps(d["payload"], sort_keys=True, separators=(",", ":"))
        if sha256_bytes(payload_json.encode("utf-8")) != d["payload_sha256"]:
            return False, "payload_sha256 mismatch"
    try:
        _check_no_secrets(d)
    except ValueError as e:
        return False, str(e)
    return True, "ok"


def manifest_new(corpus_dir, run_id, out_path):
    root = Path(corpus_dir)
    files = sorted(p for p in root.rglob("*") if p.is_file())
    entries, total = [], 0
    for p in files:
        s = p.stat().st_size
        total += s
        entries.append({"path": str(p.relative_to(root)), "size": s, "sha256": sha256_file(p)})
    art = envelope("ART-08-01", run_id, 8, 9, {"files": entries, "total_bytes": total})
    Path(out_path).write_text(json.dumps(art, indent=2) + "\n", encoding="utf-8")
    return art


def receipt_check(receipt_path, manifest_path, allowlist_path):
    rec = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    man = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    al = json.loads(Path(allowlist_path).read_text(encoding="utf-8"))
    results = []
    h = rec["payload"]["sha256"].upper()
    b = rec["payload"]["bytes"]
    al_hashes = [x.upper() for x in al["allowlist"]["sha256"]]
    cap = al["allowlist"]["max_bytes"]
    results.append(("allowlist_hash", h in al_hashes))
    results.append(("byte_cap", 0 < b <= cap))
    match = [f for f in man["payload"]["files"] if f["sha256"] == h and f["size"] == b]
    results.append(("manifest_match", len(match) == 1))
    return {k: v for k, v in results}, all(v for _, v in results)


def score(ground_truth_path, reconstruction_path, out_path):
    gt = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    rc = json.loads(Path(reconstruction_path).read_text(encoding="utf-8"))
    rc_stages = {s["stage"]: s for s in rc.get("stages", [])}
    scored, broken = [], []
    for s in gt["stages"]:
        found = s["stage"] in rc_stages
        linked = False
        if found:
            r = rc_stages[s["stage"]]
            gt_keys = {str(e.get("kind")) for e in s.get("evidence_refs", [])}
            rc_keys = {str(e.get("kind")) for e in r.get("evidence_matches", [])}
            linked = bool(gt_keys) and gt_keys.issubset(rc_keys)
        verdict = "LINKED" if linked else ("FOUND" if found else "MISSING")
        if not linked and s.get("output_artifacts"):
            broken.append(s["stage"])
        scored.append({"stage": s["stage"], "found": found, "handoff_linked": linked,
                       "verdict": verdict, "notes": ""})
    total = sum(1 for x in scored if x["verdict"] == "LINKED")
    payload = {
        "stages_scored": scored,
        "total_score": total,
        "max_score": len(scored),
        "chain_end_to_end": total == len(scored) and not broken,
        "broken_handoffs": broken,
    }
    out = envelope("ART-15-01", gt["run_id"], 15, 15, payload)
    Path(out_path).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def fixture_check(fixtures_dir):
    d = Path(fixtures_dir)
    problems = []
    for p in sorted(d.glob("*.json")):
        try:
            f = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            problems.append(f"{p.name}: unreadable ({e})")
            continue
        if f.get("synthetic") is not True:
            problems.append(f"{p.name}: missing synthetic:true")
        if not f.get("fixture_kind"):
            problems.append(f"{p.name}: missing fixture_kind")
        if f.get("fixture_kind") == "c1_correlation_alerts":
            if "alerts" not in f:
                problems.append(f"{p.name}: missing alerts")
        elif "event" not in f:
            problems.append(f"{p.name}: missing event")
    # C1 conditions (offline spec test, mirrors detection logic in docs/correlation-architecture.md):
    c1 = json.loads((d / "c1_alerts_fixture.json").read_text(encoding="utf-8"))
    by_user = {}
    for a in c1["alerts"]:
        by_user.setdefault(a["user.name"], []).append(a)
    c1_ok = False
    for user, alerts in by_user.items():
        families = {a["behavior_family"] for a in alerts}
        collection = sum(1 for a in alerts if a.get("collection_hit"))
        hosts = {a["host.name"] for a in alerts}
        c1_ok = len(families) >= 4 and collection >= 1 and len(hosts) >= 2
        if c1_ok:
            break
    if not c1_ok:
        problems.append("c1_alerts_fixture.json: C1 conditions not satisfied")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("artifact-new")
    s.add_argument("artifact_id"); s.add_argument("run_id")
    s.add_argument("producer"); s.add_argument("consumer")
    s.add_argument("--payload", required=True); s.add_argument("-o", "--out", required=True)

    s = sub.add_parser("artifact-check")
    s.add_argument("path")

    s = sub.add_parser("manifest-new")
    s.add_argument("corpus_dir"); s.add_argument("run_id")
    s.add_argument("-o", "--out", required=True)

    s = sub.add_parser("receipt-check")
    s.add_argument("receipt"); s.add_argument("manifest"); s.add_argument("allowlist")

    s = sub.add_parser("score")
    s.add_argument("ground_truth"); s.add_argument("reconstruction")
    s.add_argument("-o", "--out", required=True)

    s = sub.add_parser("fixture-check")
    s.add_argument("fixtures_dir")

    args = ap.parse_args()
    if args.cmd == "artifact-new":
        art = artifact_new(args.artifact_id, args.run_id, args.producer, args.consumer, args.payload, args.out)
        print(f"wrote {args.out} payload_sha256={art['payload_sha256']}")
    elif args.cmd == "artifact-check":
        ok, msg = artifact_check(args.path)
        print(("OK" if ok else "FAIL") + f": {args.path} -> {msg}")
        sys.exit(0 if ok else 1)
    elif args.cmd == "manifest-new":
        art = manifest_new(args.corpus_dir, args.run_id, args.out)
        print(f"wrote {args.out} files={len(art['payload']['files'])} total_bytes={art['payload']['total_bytes']}")
    elif args.cmd == "receipt-check":
        res, ok = receipt_check(args.receipt, args.manifest, args.allowlist)
        print(json.dumps(res, indent=2))
        sys.exit(0 if ok else 1)
    elif args.cmd == "score":
        out = score(args.ground_truth, args.reconstruction, args.out)
        p = out["payload"]
        print(f"score={p['total_score']}/{p['max_score']} e2e={p['chain_end_to_end']} broken={p['broken_handoffs']}")
    elif args.cmd == "fixture-check":
        problems = fixture_check(args.fixtures_dir)
        if problems:
            print("PROBLEMS:"); [print(" -", x) for x in problems]; sys.exit(1)
        print("fixtures ok (synthetic + C1 conditions satisfied)")


if __name__ == "__main__":
    main()

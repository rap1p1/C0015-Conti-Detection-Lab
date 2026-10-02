"""Tests proving the repository validator reacts to real conditions.

Uses VALIDATE_ROOT to run scripts/validate_repo.py against a synthetic tree:
  - a valid minimal ledger + manifest + receipt passes (rc=0);
  - a corrupted artifact hash fails (rc=1);
  - a mismatch between the receipt sink_files and the manifest fails (rc=1);
  - a tree without ledgers fails (rc=1).
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def _canon(raw):
    import hashlib
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest().upper()


def build_tree(target, corrupt_artifact=False, corrupt_sink=False):
    runs = target / "evidence" / "runs" / "RUN-20260101-01"
    runs.mkdir(parents=True)
    ledger_id = "RUN-20260101-01"
    ledger = {
        "run_id": ledger_id,
        "scenario_id": "C0015-LAB-1",
        "created_utc": "2026-01-01T00:00:00Z",
        "secrets_policy": "no-secrets-allowed",
        "stages": [
            {"stage": f"S{n}", "host": "WS01", "account": "C0015\\it.admin",
             "status": "NOT RUN", "input_artifacts": [], "output_artifacts": [],
             "evidence_refs": [], "notes": "test row"}
            for n in range(1, 16)
        ],
        "artifact_index": [],
    }
    body = b'{"probe": true}'
    if corrupt_artifact:
        body = b'{"probe": false}'
    (runs / "ART-08-01-TEST.json").write_bytes(body)
    ledger["artifact_index"].append({
        "artifact_id": "ART-08-01",
        "path": f"evidence/runs/{ledger_id}/ART-08-01-TEST.json",
        "sha256": _canon(b'{"probe": true}'),
        "producer_stage": "S10",
        "consumer_stage": "S11",
    })
    manifest = {"artifact_id": "ART-08-01", "run_id": ledger_id, "payload": {
        "files": [{"path": "finance/a.txt", "size": 5, "sha256": _canon(b"one\n")}]}}
    mraw = json.dumps(manifest).encode()
    (runs / "ART-08-01-RUN.json").write_bytes(mraw)
    ledger["artifact_index"].append({
        "artifact_id": "ART-08-01",
        "path": f"evidence/runs/{ledger_id}/ART-08-01-RUN.json",
        "sha256": _canon(mraw), "producer_stage": "S10", "consumer_stage": "S11"})
    sink_hash = _canon(b"one\n")
    if corrupt_sink:
        sink_hash = _canon(b"other\n")
    receipt = {
        "artifact_id": "ART-09-01", "run_id": ledger_id, "round": 1,
        "total_files": 1,
        "manifest_ref": f"evidence/runs/{ledger_id}/ART-08-01-RUN.json",
        "manifest_sha256": _canon(mraw),
        "sink_files": [{"name": "finance/a.txt", "size": 5, "sha256": sink_hash}],
    }
    (runs / "ART-09-01-round1-TEST.json").write_text(json.dumps(receipt), encoding="utf-8")
    (runs / f"{ledger_id}.json").write_text(json.dumps(ledger), encoding="utf-8")


def run_validator(target):
    env = dict(os.environ)
    env["VALIDATE_ROOT"] = str(target)
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "validate_repo.py")],
                          cwd=ROOT, capture_output=True, text=True, env=env)


class ValidatorTests(unittest.TestCase):
    def test_good_tree_passes(self):
        with tempfile.TemporaryDirectory() as td:
            build_tree(pathlib.Path(td))
            res = run_validator(pathlib.Path(td))
            self.assertEqual(res.returncode, 0, res.stdout[-800:] + res.stderr[-400:])

    def test_corrupted_artifact_fails(self):
        with tempfile.TemporaryDirectory() as td:
            build_tree(pathlib.Path(td), corrupt_artifact=True)
            res = run_validator(pathlib.Path(td))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("hash mismatch", res.stdout)

    def test_sink_manifest_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as td:
            build_tree(pathlib.Path(td), corrupt_sink=True)
            res = run_validator(pathlib.Path(td))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("sha256 mismatch", res.stdout)

    def test_missing_ledger_fails(self):
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / "evidence" / "runs").mkdir(parents=True)
            res = run_validator(pathlib.Path(td))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("no run ledgers", res.stdout)


if __name__ == "__main__":
    unittest.main()
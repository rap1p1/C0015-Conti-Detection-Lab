#!/usr/bin/env python3
"""Offline tests for C0015 lab components (stdlib unittest only).

Run from repo root:  python scripts/tests/test_offline.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import lab_tools as lt  # noqa: E402
import c2sim as c2  # noqa: E402

FIX = REPO / "scripts" / "fixtures"


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _payload(self, obj, name="p.json"):
        p = self.d / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_artifact_roundtrip(self):
        p = self._payload({"shares": [{"host": "FS01", "share": "Finance", "readable": True}]})
        out = self.d / "art.json"
        lt.artifact_new("ART-04-01", "RUN-20261001-01", 4, 6, str(p), str(out))
        ok, msg = lt.artifact_check(str(out))
        self.assertTrue(ok, msg)

    def test_artifact_tamper_detected(self):
        p = self._payload({"shares": [{"host": "FS01", "share": "Finance"}]})
        out = self.d / "art.json"
        lt.artifact_new("ART-04-01", "RUN-20261001-01", 4, 6, str(p), str(out))
        d = json.loads(out.read_text(encoding="utf-8"))
        d["payload"]["shares"][0]["share"] = "IT"
        out.write_text(json.dumps(d), encoding="utf-8")
        ok, msg = lt.artifact_check(str(out))
        self.assertFalse(ok)
        self.assertIn("sha256", msg)

    def test_artifact_rejects_secret_key(self):
        p = self._payload({"account": "C0015\\it.admin", "password": "s3cr3t"})
        with self.assertRaises(ValueError):
            lt.artifact_new("ART-05-01", "RUN-20261001-01", 7, 8, str(p), str(self.d / "a.json"))

    def test_artifact_bad_runid(self):
        p = self._payload({"x": 1})
        with self.assertRaises(ValueError):
            lt.artifact_new("ART-04-01", "RUN-bad", 4, 6, str(p), str(self.d / "a.json"))

    def test_session_token_allowed_in_artifact(self):
        p = self._payload({"session_token": "S2-0123456789abcdef"})
        out = self.d / "a.json"
        lt.artifact_new("ART-07-01", "RUN-20261001-01", 7, 8, str(p), str(out))
        ok, _ = lt.artifact_check(str(out))
        self.assertTrue(ok)

    def test_manifest_receipt_chain(self):
        corpus = self.d / "corpus"
        corpus.mkdir()
        (corpus / "payroll-notes.txt").write_bytes(b"Payroll Notes\r\n\r\n")
        (corpus / "budget-q3.txt").write_bytes(b"budget data")
        man = self.d / "manifest.json"
        lt.manifest_new(str(corpus), "RUN-20261001-01", str(man))
        m = json.loads(man.read_text(encoding="utf-8"))
        target = next(f for f in m["payload"]["files"] if f["path"] == "payroll-notes.txt")
        allow = self.d / "allowlist.json"
        allow.write_text(json.dumps({"allowlist": {"sha256": [target["sha256"]], "max_bytes": 1024}}), encoding="utf-8")
        # valid receipt
        rec_ok = self.d / "rec_ok.json"
        rec_ok.write_text(json.dumps({"payload": {"sha256": target["sha256"], "bytes": target["size"], "client_ip": "192.168.50.30"}}), encoding="utf-8")
        res, ok = lt.receipt_check(str(rec_ok), str(man), str(allow))
        self.assertTrue(ok, res)
        # wrong hash
        rec_bad = self.d / "rec_bad.json"
        rec_bad.write_text(json.dumps({"payload": {"sha256": "A" * 64, "bytes": target["size"]}}), encoding="utf-8")
        res, ok = lt.receipt_check(str(rec_bad), str(man), str(allow))
        self.assertFalse(ok)
        self.assertFalse(res["allowlist_hash"])
        # oversize
        rec_big = self.d / "rec_big.json"
        rec_big.write_text(json.dumps({"payload": {"sha256": target["sha256"], "bytes": 99999}}), encoding="utf-8")
        res, ok = lt.receipt_check(str(rec_big), str(man), str(allow))
        self.assertFalse(ok)
        self.assertFalse(res["byte_cap"])


class ScoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _gt(self):
        return {
            "run_id": "RUN-20261001-01",
            "stages": [
                {"stage": "S1", "output_artifacts": [], "evidence_refs": [{"kind": "E1-chain"}]},
                {"stage": "S2", "output_artifacts": [], "evidence_refs": [{"kind": "E7-hash"}]},
                {"stage": "S3", "output_artifacts": ["session1"], "evidence_refs": [{"kind": "receipt"}]},
            ],
        }

    def _score(self, gt, rec):
        gtp = self.d / "gt.json"
        rcp = self.d / "rec.json"
        out = self.d / "s.json"
        gtp.write_text(json.dumps(gt), encoding="utf-8")
        rcp.write_text(json.dumps(rec), encoding="utf-8")
        return lt.score(str(gtp), str(rcp), str(out))

    def test_missing_stage_breaks_chain(self):
        gt = self._gt()
        rec = {"stages": [
            {"stage": "S1", "evidence_matches": [{"kind": "E1-chain"}]},
            {"stage": "S2", "evidence_matches": [{"kind": "E7-hash"}]},
        ]}
        out = self._score(gt, rec)
        self.assertFalse(out["payload"]["chain_end_to_end"])
        self.assertIn("S3", out["payload"]["broken_handoffs"])

    def test_all_linked_is_e2e(self):
        gt = self._gt()
        rec = {"stages": [
            {"stage": "S1", "evidence_matches": [{"kind": "E1-chain"}]},
            {"stage": "S2", "evidence_matches": [{"kind": "E7-hash"}]},
            {"stage": "S3", "evidence_matches": [{"kind": "receipt"}]},
        ]}
        out = self._score(gt, rec)
        self.assertTrue(out["payload"]["chain_end_to_end"])


class C2SimTests(unittest.TestCase):
    def setUp(self):
        c2.STATE["sessions"].clear()
        self._tmp = tempfile.TemporaryDirectory()
        c2.OPTS["ledger_dir"] = Path(self._tmp.name)

    def tearDown(self):
        c2.STATE["sessions"].clear()
        self._tmp.cleanup()

    def test_token_format(self):
        self.assertTrue(c2.token_ok("S2-0123456789abcdef"))
        self.assertFalse(c2.token_ok("S2-xyz"))
        self.assertFalse(c2.token_ok(None))

    def test_register_rules(self):
        ok, msg = c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", "192.168.50.20")
        self.assertTrue(ok, msg)
        # same token re-registers (elevated beacon handoff) and keeps the session
        ok, msg = c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", "192.168.50.20")
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "re-registered")
        self.assertFalse(c2.register_ok("phase3", "FS01", "S1-0123456789abcdef", None)[0])  # same token, wrong host
        self.assertFalse(c2.register_ok("phase7-session2", "WS01", "S2-0123456789abcdef", None)[0])  # wrong host
        self.assertFalse(c2.register_ok("evil-stage", "FS01", "S2-0123456789abcdef", None)[0])
        self.assertFalse(c2.register_ok("phase3", "WS01", "bad-token", None)[0])

    def test_register_reuse_same_run(self):
        ok, _ = c2.register_ok("phase3", "WS01", "S1-aaaaaaaaaaaaaaaa", None, run_id="RUN-20261001-01")
        self.assertTrue(ok)
        # same stage/host/run with a different token -> idempotent reuse
        ok, msg = c2.register_ok("phase3", "WS01", "S1-bbbbbbbbbbbbbbbb", None, run_id="RUN-20261001-01")
        self.assertFalse(ok)
        self.assertEqual(msg, "reuse:S1-aaaaaaaaaaaaaaaa")
        # different run_id -> new session allowed
        ok, _ = c2.register_ok("phase3", "WS01", "S1-cccccccccccccccc", None, run_id="RUN-20261001-02")
        self.assertTrue(ok)

    def test_task_sequence_and_cap(self):
        c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", None)
        # the discovery batch is served once in order, then T-BEACON-SLEEP (idle)
        expected = [
            "T-DISCOVER-CORPUS", "T-DISCOVER-SYSTEM", "T-DISCOVER-DOMAINGROUPS",
            "T-DISCOVER-LOCALGROUPS", "T-DISCOVER-TRUSTS", "T-DISCOVER-NETVIEWALL",
            "T-DISCOVER-TIME", "T-DISCOVER-PING", "T-BEACON-SLEEP",
        ]
        for i, t in enumerate(expected):
            task, cmd, _ = c2.next_task("S1-0123456789abcdef")
            self.assertEqual(task, t, f"step {i}")
            self.assertIsNone(cmd)
            ok, _ = c2.result_ok("S1-0123456789abcdef", t, 100)
            self.assertTrue(ok)
        # exhausted batch -> idle sleep
        self.assertEqual(c2.next_task("S1-0123456789abcdef"), ("T-BEACON-SLEEP", None, 0))
        # v3: task names are no longer allowlisted, but the result cap applies
        self.assertTrue(c2.result_ok("S1-0123456789abcdef", "T-ANY", 128)[0])
        self.assertFalse(c2.result_ok("S1-0123456789abcdef", "T-NOOP", c2.MAX_RESULT_BYTES + 1)[0])
        c2.OPTS["max_result"] = 2048
        self.assertFalse(c2.result_ok("S1-0123456789abcdef", "T-NOOP", 4096)[0])
        c2.OPTS["max_result"] = c2.MAX_RESULT_BYTES

    def test_dynamic_op_cmd_v3(self):
        # v3 dynamic tasking: operator-entered benign commands take priority
        c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", None)
        ok, msg = c2.enqueue_cmd("S1-0123456789abcdef", "whoami /all")
        self.assertTrue(ok, msg)
        self.assertEqual(c2.next_task("S1-0123456789abcdef"), ("OP-CMD", "whoami /all", 0))
        self.assertTrue(c2.result_ok("S1-0123456789abcdef", "OP-CMD", 512)[0])
        # queued op-command is served before the fixed batch continues
        c2.enqueue_cmd("S1-0123456789abcdef", "ipconfig")
        task, cmd, _ = c2.next_task("S1-0123456789abcdef")
        self.assertEqual((task, cmd), ("OP-CMD", "ipconfig"))
        # guards: empty, credential-like, unknown session
        self.assertFalse(c2.enqueue_cmd("S1-0123456789abcdef", "  ")[0])
        self.assertFalse(c2.enqueue_cmd("S1-0123456789abcdef", "net use /user:x password=secret *")[0])
        self.assertFalse(c2.enqueue_cmd("S2-f000000000000000", "whoami")[0])
        # oversized raw command rejected
        self.assertFalse(c2.enqueue_cmd("S1-0123456789abcdef", "cmd" * 3000)[0])

    def test_runbook_enqueue_v3(self):
        # v3.1: ordered kill-chain template enqueues with per-command pause
        c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", None)
        entries = [
            {"cmd": "whoami /all", "pause": 2},
            {"cmd": "net view /all"},
            {"cmd": "C:\\Tools\\mimikatz.exe sekurlsa::logonpasswords /out:C:\\C0015\\lsass.dmp", "pause": 5},
        ]
        ok, msg = c2.enqueue_runbook("S1-0123456789abcdef", entries)
        self.assertTrue(ok, msg)
        self.assertEqual(c2.next_task("S1-0123456789abcdef"), ("OP-CMD", "whoami /all", 2))
        self.assertEqual(c2.next_task("S1-0123456789abcdef"), ("OP-CMD", "net view /all", 0))
        t, cmd, pause = c2.next_task("S1-0123456789abcdef")
        self.assertEqual(t, "OP-CMD")
        self.assertIn("mimikatz.exe", cmd)
        self.assertEqual(pause, 5)
        # guards: credential-like entry and unknown session rejected
        self.assertFalse(c2.enqueue_runbook("S1-0123456789abcdef", [{"cmd": "net use /user:x password=secret"}])[0])
        self.assertFalse(c2.enqueue_runbook("S2-f000000000000000", entries)[0])

    def test_result_output_ring_v32(self):
        # v3.2: command OUTPUT is stored in memory so the C2 operator can read it remotely
        c2.register_ok("phase3", "WS01", "S1-0123456789abcdef", None)
        self.assertTrue(c2.result_ok("S1-0123456789abcdef", "OP-CMD", 11, body=b"net view OK")[0])
        r = c2.results_for("S1-0123456789abcdef", 5)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[-1]["output"], "net view OK")
        self.assertEqual(r[-1]["task"], "OP-CMD")
        for i in range(40):  # ring is bounded
            c2.result_ok("S1-0123456789abcdef", "T-%d" % i, 2, body=b"x")
        self.assertLessEqual(len(c2.results_for("S1-0123456789abcdef", 100)), 32)
        self.assertIsNone(c2.results_for("S2-f000000000000000"))
        # size cap still enforced
        self.assertFalse(c2.result_ok("S1-0123456789abcdef", "T-NOOP", c2.MAX_RESULT_BYTES + 1)[0])

    def test_register_reregister_same_token_v32(self):
        # v3.2: the SAME token may re-register (elevated beacon handoff) keeping queue/results
        tok = "S1-aaaaaaaaaaaaaaaa"
        self.assertTrue(c2.register_ok("phase3", "WS01", tok, "192.168.50.20")[0])
        c2.enqueue_cmd(tok, "whoami /all")
        ok, msg = c2.register_ok("phase3", "WS01", tok, "192.168.50.20")
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "re-registered")
        self.assertEqual(c2.next_task(tok), ("OP-CMD", "whoami /all", 0))  # queue preserved across re-register
        # different host under the same token is still rejected
        self.assertFalse(c2.register_ok("phase3", "FS01", tok, "192.168.50.30")[0])

    def test_session2_receipt_written(self):
        tok = "S2-0123456789abcdef"
        c2.register_ok("phase7-session2", "FS01", tok, "192.168.50.30")
        r = c2.make_session2_receipt("RUN-20261001-01", tok, "192.168.50.30")
        self.assertIsNotNone(r)
        self.assertTrue(Path(r["path"]).is_file())
        ok, msg = lt.artifact_check(r["path"])
        self.assertTrue(ok, msg)
        self.assertEqual(r["artifact"]["payload"]["host"], "FS01")


class FixtureTests(unittest.TestCase):
    def test_all_fixtures_synthetic_and_c1_conditions(self):
        problems = lt.fixture_check(str(FIX))
        self.assertEqual(problems, [])

    def test_e3_fixture_models_attribution_gap(self):
        d = json.loads((FIX / "e3_network_unknown_process.json").read_text(encoding="utf-8"))
        self.assertTrue(d["synthetic"])
        self.assertEqual(d["event"]["process"]["entity_id"], "00000000-0000-0000-0000-000000000000")
        self.assertIsNone(d["event"]["process"]["name"])

    def test_e10_lsass_fixture_is_synthetic_branch_only(self):
        d = json.loads((FIX / "e10_lsass_probe.json").read_text(encoding="utf-8"))
        self.assertTrue(d["synthetic"])
        self.assertEqual(d["event"]["target"]["name"], "lsass.exe")


if __name__ == "__main__":
    unittest.main(verbosity=2)


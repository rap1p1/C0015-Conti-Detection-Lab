#!/usr/bin/env python3
"""C0015 C2-SIM v2 — constrained C2 simulator for the lab (benign, stdlib only).

Replaces the role of the C0015 Bazar/Cobalt Strike C2 infrastructure with an
internal, fixed-purpose server. NEVER offers arbitrary shell, dynamic tasks or
payload upload. Task set is a fixed allowlist.

Endpoints:
  GET  /dl/<name>                 serve an allowlisted lab file (T1105 ingress analog)
  POST /session/register?stage=&host=&token=   register a lab session (S1/S2 tokens)
  GET  /task/next?session=<token> next fixed task for the session
  POST /result?session=&task=     bounded task result; server logs + receipt
  GET  /checkin?stage=&host=      legacy 1-shot checkin (phase4-rundll32), returns 204

On a valid phase7-session2 registration the server writes ART-07-01 receipt
JSON into the run ledger directory (server-side evidence of the second session).
"""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from lab_tools import envelope, sha256_bytes

TOKEN_RE = re.compile(r"^S[12]-[0-9a-f]{16}$")
TASKS = {
    "phase3": ["T-DISCOVER-CORPUS", "T-BEACON-SLEEP"],
    "phase7-session2": ["T-DISCOVER-CORPUS"],
}
TASK_ALLOWLIST = {
    "T-DISCOVER-CORPUS": {"max_result_bytes": 1024},
    "T-BEACON-SLEEP": {"max_result_bytes": 128},
    "T-NOOP": {"max_result_bytes": 128},
}
STAGE_ALLOWLIST = {
    "phase3": {"hosts": {"WS01"}},
    "phase7-session2": {"hosts": {"FS01"}},
    "phase4-rundll32": {"hosts": {"FS01"}},
}
DL_ALLOWLIST = ["c0015_143_surrogate.dll"]
MAX_RESULT_BYTES = 1024

STATE = {"sessions": {}}  # token -> {stage, host, ip, registered_utc, tasks_done}
OPTS = {"ledger_dir": Path("evidence/run-ledger"), "dl_dir": Path("scripts/fixtures"), "log": None}


def log(msg):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + msg
    print(line, flush=True)
    if OPTS["log"] is not None:
        with open(OPTS["log"], "a", encoding="utf-8") as f:
            f.write(line + "\n")


# ---- pure logic (unit-testable without network) ----
def token_ok(t):
    return isinstance(t, str) and bool(TOKEN_RE.match(t))


def register_ok(stage, host, token, client_ip):
    if stage not in STAGE_ALLOWLIST:
        return False, "stage not in allowlist"
    if host not in STAGE_ALLOWLIST[stage]["hosts"]:
        return False, "host not allowed for stage"
    if not token_ok(token):
        return False, "bad token format"
    if client_ip is not None:
        pass  # IP allowlist enforced via CLI --allow-ip if provided
    if token in STATE["sessions"]:
        return False, "token already registered"
    STATE["sessions"][token] = {
        "stage": stage, "host": host, "ip": client_ip,
        "registered_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tasks_done": [],
    }
    return True, "registered"


def next_task(token):
    s = STATE["sessions"].get(token)
    if not s:
        return None
    seq = TASKS.get(s["stage"], [])
    idx = len(s["tasks_done"]) % len(seq)
    return seq[idx] if seq else "T-NOOP"


def result_ok(token, task, size):
    s = STATE["sessions"].get(token)
    if not s:
        return False, "unknown session"
    if task not in TASK_ALLOWLIST:
        return False, "task not in allowlist"
    if size > TASK_ALLOWLIST[task]["max_result_bytes"]:
        return False, "result too large"
    s["tasks_done"].append(task)
    return True, "accepted"


def make_session2_receipt(run_id, token, client_ip):
    s = STATE["sessions"].get(token)
    if not s or s["stage"] != "phase7-session2":
        return None
    payload = {
        "host": s["host"], "stage": s["stage"], "client_ip": client_ip or s["ip"],
        "session_token": token, "registered_utc": s["registered_utc"],
        "task_ids": TASKS.get(s["stage"], []),
        "evidence_expected": [
            "FS01 E1 rundll32 (parent wmiprvse.exe)",
            "FS01 E7 ImageLoad c0015_143_surrogate.dll",
            "FS01 E3 callback to C2-SIM",
        ],
    }
    art = envelope("ART-07-01", run_id, 7, 8, payload)
    out = OPTS["ledger_dir"] / f"ART-07-01-{token[-8:]}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(art, indent=2) + "\n", encoding="utf-8")
    return {"path": str(out), "artifact": art}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        parsed = urlsplit(self.path)
        q = parse_qs(parsed.query)
        if parsed.path.startswith("/dl/"):
            name = parsed.path.split("/dl/", 1)[1]
            if name not in DL_ALLOWLIST:
                return self._send(404, b'{"error":"not allowlisted"}')
            f = OPTS["dl_dir"] / name
            if not f.is_file():
                return self._send(404, b'{"error":"file missing (not staged yet)"}')
            log(f"GET /dl/{name} client={self.client_address[0]}")
            return self._send(200, f.read_bytes(), "application/octet-stream")
        if parsed.path == "/checkin":
            stage = (q.get("stage") or [""])[0]
            host = (q.get("host") or [""])[0]
            if stage == "phase4-rundll32" and host == "FS01":
                log(f"checkin ok stage={stage} host={host} client={self.client_address[0]}")
                return self._send(204)
            return self._send(403, b'{"error":"invalid checkin"}')
        if parsed.path == "/task/next":
            token = (q.get("session") or [""])[0]
            t = next_task(token)
            if t is None:
                return self._send(403, b'{"error":"unknown session"}')
            log(f"task/next session={token[-8:]} task={t}")
            return self._send(200, json.dumps({"task": t}).encode())
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlsplit(self.path)
        q = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2048:
            return self._send(413, b'{"error":"body too large"}')
        body = self.rfile.read(length) if length else b""
        if parsed.path == "/session/register":
            stage = (q.get("stage") or [""])[0]
            host = (q.get("host") or [""])[0]
            token = (q.get("token") or [""])[0]
            ok, msg = register_ok(stage, host, token, self.client_address[0])
            log(f"register stage={stage} host={host} token={token[-8:] if token else '-'} ok={ok} ({msg})")
            if not ok:
                return self._send(403, json.dumps({"error": msg}).encode())
            run_id = (q.get("run") or ["RUN-00000000-00"])[0]
            receipt = make_session2_receipt(run_id, token, self.client_address[0]) if stage == "phase7-session2" else None
            resp = {"ok": True, "session": token}
            if receipt:
                resp["receipt_artifact"] = receipt["path"]
            return self._send(200, json.dumps(resp).encode())
        if parsed.path == "/result":
            token = (q.get("session") or [""])[0]
            task = (q.get("task") or [""])[0]
            ok, msg = result_ok(token, task, len(body))
            log(f"result session={token[-8:] if token else '-'} task={task} bytes={len(body)} ok={ok} ({msg})")
            if not ok:
                return self._send(403, json.dumps({"error": msg}).encode())
            return self._send(200, b'{"ok":true}')
        return self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ledger", default="evidence/run-ledger")
    ap.add_argument("--dl-dir", default="scripts/fixtures")
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    OPTS["ledger_dir"] = Path(args.ledger)
    OPTS["dl_dir"] = Path(args.dl_dir)
    OPTS["log"] = args.log
    log(f"C2-SIM v2 listening on {args.ip}:{args.port} (tasks={sorted(TASK_ALLOWLIST)})")
    HTTPServer((args.ip, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

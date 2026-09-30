#!/usr/bin/env python3
"""C0015 C2-SIM v3 — lab C2 simulator for the operator phase (benign, stdlib only).

Operator-realistic: the C2 host can enqueue ARBITRARY BENIGN commands to a
session via POST /cmd (dynamic tasking, like a real C2 operator); the beacon
executes them and returns the result. The fixed discovery batch from the
blueprint is still served as the default task stream while no operator command
is queued.

Safety retained (project hard lines): real malware/payload upload stays refused
(/dl allowlist only), credentials/secret strings on the wire or in logs are
rejected, and stage/host/token validation + per-run dedup are unchanged.

Endpoints:
  GET  /dl/<name>                 serve an allowlisted lab file (T1105 ingress analog)
  POST /session/register?stage=&host=&token=   register a lab session (S1/S2 tokens)
  GET  /task/next?session=<token> next task for the session; {"task": name, "cmd": raw|null, "pause": sec}
  POST /cmd?session=<token>       enqueue a raw benign command (body = command string)
  POST /runbook?session=<token>&name=<killchain>  enqueue an ordered kill-chain template (scripts/runbooks/)
  POST /result?session=&task=     task result (bounded by --max-result); server logs + receipt
  GET  /sessions                   operator console: active lab sessions (full tokens, queue/task state)
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
    # S4 discovery batch (exact DFIR commands), served once each in order,
    # then the beacon idles on T-BEACON-SLEEP until the next run.
    "phase3": [
        "T-DISCOVER-CORPUS",       # net view /all                       (T1135)
        "T-DISCOVER-SYSTEM",       # tasklist /s                         (T1057)
        "T-DISCOVER-DOMAINGROUPS", # net group "domain admins" /dom      (T1069.002)
        "T-DISCOVER-LOCALGROUPS",  # net localgroup "administrator"      (T1069.001)
        "T-DISCOVER-TRUSTS",       # nltest /domain_trusts /all_trusts   (T1482)
        "T-DISCOVER-NETVIEWALL",   # net view /all /domain               (T1018)
        "T-DISCOVER-TIME",         # net view /all time                  (T1124)
        "T-DISCOVER-PING",         # ping -n 1 <target>                  (T1018)
        "T-BEACON-SLEEP",
    ],
    "phase7-session2": ["T-DISCOVER-CORPUS"],
}
STAGE_ALLOWLIST = {
    "phase3": {"hosts": {"WS01"}},
    "phase7-session2": {"hosts": {"FS01"}},
    "phase4-rundll32": {"hosts": {"FS01"}},
}
DL_ALLOWLIST = ["c0015_143_surrogate.dll"]
MAX_RESULT_BYTES = 262144   # v3: per-command result bound (configurable via --max-result)
MAX_CMD_BYTES = 4096        # cap for one operator-entered command string

STATE = {"sessions": {}}  # token -> {stage, host, ip, registered_utc, tasks_done, queue}
OPTS = {"ledger_dir": Path("evidence/run-ledger"), "dl_dir": Path("scripts/fixtures"),
        "log": None, "max_result": MAX_RESULT_BYTES, "runbook_dir": Path("scripts/runbooks"),
        "max_queue": 64}


def log(msg):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + msg
    print(line, flush=True)
    if OPTS["log"] is not None:
        with open(OPTS["log"], "a", encoding="utf-8") as f:
            f.write(line + "\n")


# ---- pure logic (unit-testable without network) ----
def token_ok(t):
    return isinstance(t, str) and bool(TOKEN_RE.match(t))


def register_ok(stage, host, token, client_ip, run_id=None):
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
    # Idempotency: reuse the existing session for the same (stage, host, run).
    # A repeated open of the entry document (or both Word auto macros firing)
    # would otherwise create duplicate beacon sessions and corrupt the run
    # evidence. run_id is carried in the register query and stored with the
    # session; None means "no run context" (legacy callers) -> keep them unique.
    if run_id is not None:
        for t, s in STATE["sessions"].items():
            if s.get("stage") == stage and s.get("host") == host and s.get("run") == run_id:
                return False, "reuse:" + t
    STATE["sessions"][token] = {
        "stage": stage, "host": host, "ip": client_ip,
        "run": run_id,
        "registered_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tasks_done": [],
        "queue": [],  # operator-enqueued raw commands (v3 dynamic tasking)
    }
    return True, "registered"


def enqueue_cmd(token, cmd):
    """v3: operator-entered benign command for the session (queued, executed by the beacon)."""
    s = STATE["sessions"].get(token)
    if not s:
        return False, "unknown session"
    cmd = (cmd or "").strip()
    if not cmd:
        return False, "empty command"
    if len(cmd.encode("utf-8")) > MAX_CMD_BYTES:
        return False, "command too long"
    # no-secrets rule: never push a credential-looking string onto the wire/logs
    low = cmd.lower()
    for bad in ("password=", " /password:", " -password ", " pass "):
        if bad in low:
            return False, "rejected: credential-like string on the command line"
    s["queue"].append({"cmd": cmd, "pause": 0})
    return True, "queued"


def enqueue_runbook(token, entries):
    """v3.1: enqueue an ordered kill-chain template (list of {"cmd","pause"})."""
    s = STATE["sessions"].get(token)
    if not s:
        return False, "unknown session"
    if len(s["queue"]) + len(entries) > OPTS.get("max_queue", 64):
        return False, "queue full"
    for e in entries:
        cmd = str(e.get("cmd", "")).strip()
        if not cmd:
            continue
        low = cmd.lower()
        if any(b in low for b in ("password=", " /password:", " -password ", " pass ")):
            return False, "rejected: credential-like string in runbook"
        try:
            pause = max(0, int(e.get("pause", 0) or 0))
        except Exception:
            pause = 0
        s["queue"].append({"cmd": cmd, "pause": pause})
    return True, "queued"


def next_task(token):
    """Returns (task_name, raw_cmd_or_None, pause_sec). Operator commands (OP-CMD)
    take priority; otherwise the fixed discovery batch is served once, then idle."""
    s = STATE["sessions"].get(token)
    if not s:
        return None, None, None
    if s["queue"]:
        it = s["queue"].pop(0)
        return "OP-CMD", it["cmd"], it.get("pause", 0)
    seq = TASKS.get(s["stage"], [])
    idx = len(s["tasks_done"])
    if not seq:
        return "T-NOOP", None, 0
    if idx >= len(seq):
        return "T-BEACON-SLEEP", None, 0
    return seq[idx], None, 0


def result_ok(token, task, size):
    s = STATE["sessions"].get(token)
    if not s:
        return False, "unknown session"
    if size > OPTS.get("max_result", MAX_RESULT_BYTES):
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
        if parsed.path == "/sessions":
            # operator console: active lab sessions (lab-internal; tokens are lab
            # session tokens, never credentials). Nothing secret is echoed.
            lst = [{"token": t, "stage": s.get("stage"), "host": s.get("host"),
                    "ip": s.get("ip"), "registered_utc": s.get("registered_utc"),
                    "queue_len": len(s.get("queue", [])), "tasks_done": len(s.get("tasks_done", []))}
                   for t, s in STATE["sessions"].items()]
            return self._send(200, json.dumps(lst).encode())
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
            t, cmd, pause = next_task(token)
            if t is None:
                return self._send(403, b'{"error":"unknown session"}')
            log(f"task/next session={token[-8:]} task={t}" + (f" cmd={cmd}" if cmd else ""))
            body = {"task": t}
            if cmd is not None:
                body["cmd"] = cmd
            if pause:
                body["pause"] = pause
            return self._send(200, json.dumps(body).encode())
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlsplit(self.path)
        q = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        if length > OPTS.get("max_result", MAX_RESULT_BYTES) + 8192:
            return self._send(413, b'{"error":"body too large"}')
        body = self.rfile.read(length) if length else b""
        if parsed.path == "/session/register":
            stage = (q.get("stage") or [""])[0]
            host = (q.get("host") or [""])[0]
            token = (q.get("token") or [""])[0]
            run_id = (q.get("run") or ["RUN-00000000-00"])[0]
            ok, msg = register_ok(stage, host, token, self.client_address[0], run_id=run_id)
            log(f"register stage={stage} host={host} token={token[-8:] if token else '-'} ok={ok} ({msg})")
            if not ok:
                if msg.startswith("reuse:"):
                    # idempotent: a duplicate registration for the same
                    # (stage, host, run) reuses the existing session token.
                    reused = msg.split(":", 1)[1]
                    resp = {"ok": True, "session": reused, "reused": True}
                    return self._send(200, json.dumps(resp).encode())
                return self._send(403, json.dumps({"error": msg}).encode())
            receipt = make_session2_receipt(run_id, token, self.client_address[0]) if stage == "phase7-session2" else None
            resp = {"ok": True, "session": token, "reused": False}
            if receipt:
                resp["receipt_artifact"] = receipt["path"]
            return self._send(200, json.dumps(resp).encode())
        if parsed.path == "/cmd":
            token = (q.get("session") or [""])[0]
            try:
                cmd = body.decode("utf-8", "replace")
            except Exception:
                cmd = ""
            ok, msg = enqueue_cmd(token, cmd)
            log(f"op-cmd session={token[-8:] if token else '-'} cmd={(cmd or '')[:80]} ok={ok} ({msg})")
            if not ok:
                return self._send(403, json.dumps({"error": msg}).encode())
            return self._send(200, b'{"ok":true}')
        if parsed.path == "/runbook":
            token = (q.get("session") or [""])[0]
            name = (q.get("name") or [""])[0].strip()
            rb = Path(OPTS.get("runbook_dir", "scripts/runbooks")) / ("%s.json" % name)
            if not rb.is_file():
                return self._send(404, json.dumps({"error": "unknown runbook"}).encode())
            try:
                entries = json.loads(rb.read_text(encoding="utf-8")).get("entries", [])
            except Exception as ex:
                return self._send(500, json.dumps({"error": "runbook unreadable"}).encode())
            ok, msg = enqueue_runbook(token, entries)
            log(f"op-runbook session={token[-8:] if token else '-'} name={name} entries={len(entries)} ok={ok} ({msg})")
            if not ok:
                return self._send(403, json.dumps({"error": msg}).encode())
            return self._send(200, json.dumps({"ok": True, "entries": len(entries)}).encode())
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
    ap.add_argument("--max-result", type=int, default=MAX_RESULT_BYTES)
    ap.add_argument("--runbook-dir", default="scripts/runbooks")
    args = ap.parse_args()
    OPTS["ledger_dir"] = Path(args.ledger)
    OPTS["dl_dir"] = Path(args.dl_dir)
    OPTS["log"] = args.log
    OPTS["max_result"] = args.max_result
    OPTS["runbook_dir"] = Path(args.runbook_dir)
    log(f"C2-SIM v3 listening on {args.ip}:{args.port} (max_result={args.max_result})")
    HTTPServer((args.ip, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

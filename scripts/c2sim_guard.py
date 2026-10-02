#!/usr/bin/env python3
"""c2sim_guard.py — watchdog for the lab C2-SIM server (gap G8).

Problem (run RUN-20260930-01): the C2-SIM process died at 03:04:38Z mid-run and
was only restarted manually next day, leaving a telemetry/evidence gap. Root cause
was never captured: the launcher started c2sim with a hidden window so the crash
stderr went nowhere.

The guard:
  - spawns the guarded command (c2sim_v2.py) with stdout/stderr captured into a
    persistent error log (crash diagnostics land in the repo, not nowhere)
  - respawns the child automatically after any exit (3 s backoff)
  - reports every start/exit/restart count into the error log
  - watches a stop-flag file: when launch_servers.ps1 -Stop writes it, the guard
    terminates the child and exits (no zombie reboots)
  - writes the current child PID to a state file so -Stop can also kill it directly

Usage (via payloads/packaging/launch_servers.ps1):
  python scripts/c2sim_guard.py --cmd "python scripts/c2sim_v2.py --ip 192.168.50.1 --port 8080 --ledger evidence/run-ledger --log c2sim.log" --state .c2sim-child.pid --stopflag .c2sim.stop --log c2sim.err.log
"""
import argparse
import os
import subprocess
import time


def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cmd", required=True, help="guarded command line (space-split; our call is fixed and unquoted)")
    ap.add_argument("--state", default=".c2sim-child.pid", help="file holding the CURRENT child PID")
    ap.add_argument("--stopflag", default=".c2sim.stop", help="stop-flag file watched by the guard")
    ap.add_argument("--log", default="c2sim.err.log", help="captured child stdout/stderr + guard events")
    ap.add_argument("--backoff", type=int, default=3, help="seconds between respawns")
    args = ap.parse_args()

    cmd = args.cmd.split()
    if not cmd:
        raise SystemExit("no command")

    def write_pid(pid):
        try:
            with open(args.state, "w") as f:
                f.write(str(pid) if pid else "")
        except Exception:
            pass

    def logf_write(f, line):
        try:
            f.write(line + "\n")
            f.flush()
        except Exception:
            pass

    write_pid(0)
    restarts = 0
    while True:
        if os.path.exists(args.stopflag):
            with open(args.log, "a") as f:
                logf_write(f, ts() + " guard: stop flag present, exiting without start")
            return 0
        err = open(args.log, "a", encoding="utf-8", errors="replace")
        logf_write(err, ts() + " guard: START restarts=%d cmd=%s" % (restarts, " ".join(cmd)))
        # CREATE_NO_WINDOW keeps the child off the operator's console (same as before)
        proc = subprocess.Popen(cmd, stdout=err, stderr=subprocess.STDOUT,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        write_pid(proc.pid)
        while True:
            if os.path.exists(args.stopflag):
                logf_write(err, ts() + " guard: stop flag set - terminating child")
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                logf_write(err, ts() + " guard: stopped (child rc=%s)" % proc.returncode)
                err.close()
                write_pid(0)
                return 0
            rc = proc.poll()
            if rc is not None:
                logf_write(err, ts() + " guard: child EXITED rc=%s -> respawn in %ds (restarts=%d)"
                           % (rc, args.backoff, restarts + 1))
                err.close()
                write_pid(0)
                restarts += 1
                time.sleep(args.backoff)
                break
            time.sleep(2)


if __name__ == "__main__":
    main()
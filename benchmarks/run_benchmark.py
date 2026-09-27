"""Full-pipeline benchmark: research depth vs scanner count.

Starts the local mock app, drives the real CLI end to end (katana + nuclei
included), and prints the comparison that matters:

    scanner findings  vs  hypotheses tested  vs  validated findings

Usage:
    PYTHONPATH=$(pwd) python3 benchmarks/run_benchmark.py [--no-scan]

Local target only. Never point this at a real program.
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mock_app

BRIEF = """In scope:
- %s
Rules:
Automated scanning is allowed. Active testing is permitted. No denial of service.
"""


def cli(ws, *args):
    cmd = [sys.executable, "-m", "bbagent.cli", "--workspace", ws] + list(args)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["BB_TOKEN_A"] = mock_app.TOKEN_A
    env["BB_TOKEN_B"] = mock_app.TOKEN_B
    print("\n$ bbagent %s" % " ".join(args))
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    sys.stdout.write(p.stdout)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
    return p


def main() -> int:
    active = "--no-scan" not in sys.argv
    srv, port = mock_app.serve()
    base = "http://127.0.0.1:%d/" % port
    print("mock app: %s  (boring to a scanner, broken for two identities)" % base)

    ws = tempfile.mkdtemp(prefix="bbagent-bench-")
    brief = os.path.join(ws, "scope.txt")
    with open(brief, "w") as f:
        f.write(BRIEF % base)
    try:
        cli(ws, "program", "--brief", brief, "--url", base, "--name", "mock-benchmark")
        cli(ws, "confirm")
        cli(ws, "account", "A", "--role", "user", "--token", "Authorization=env:BB_TOKEN_A",
            "--identity", "alice", "--owns", "1042")
        cli(ws, "account", "B", "--role", "user", "--token", "Authorization=env:BB_TOKEN_B",
            "--identity", "bob", "--owns", "1043")
        # The scanner pass gets its own wall clock. A full nuclei template set
        # against this app takes 20+ minutes and finds nothing -- that is the
        # baseline this benchmark exists to beat, but it must not eat the research
        # budget, or the run stops before it reasons about anything.
        recon = ["recon", "--tool-timeout", "1800"] + (
            ["--active", "--approve", "nuclei"] if active else [])
        cli(ws, *recon)
        # research runs on the surface recon already found; the scanners are done
        research = ["research", "--max-seconds", "900", "--tool-timeout", "120"]
        cli(ws, *research)
        cli(ws, "hypotheses")
        cli(ws, "findings")
        cli(ws, "researchlog")
        cli(ws, "researchreport")
        print("\nworkspace kept at %s" % ws)
        return 0
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())

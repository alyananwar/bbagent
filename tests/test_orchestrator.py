import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import Engagement, ProgramPermissions, RuleKind, ScopePolicy, ScopeRule
from bbagent.db import DB
from bbagent.orchestrator import Orchestrator
from bbagent import sandbox


def _policy(active=True):
    return ScopePolicy(
        in_scope=[ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.acme.com"),
                  ScopeRule(RuleKind.DOMAIN, "acme.com")],
        permissions=ProgramPermissions(active_testing_allowed=active, automated_scanning_allowed=active),
    )


def test_run_recon_records_outcomes():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="acme"))
        orch = Orchestrator(db, eng, _policy())
        summary = orch.run_recon()
        # tools aren't installed in CI, so steps land in not_installed, but the
        # gate ran and logged decisions
        total = sum(len(v) for v in summary.values())
        assert total > 0
        # scope decisions were logged
        rows = db.conn.execute("SELECT COUNT(*) c FROM scope_decisions WHERE engagement_id=?",
                               (eng,)).fetchone()
        assert rows["c"] > 0
        db.close()


def test_nuclei_needs_approval_when_not_approved():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="acme"))
        orch = Orchestrator(db, eng, _policy())
        # seed a URL so expand_plan proposes nuclei
        from bbagent.graph import Node
        orch.graph.add(Node("url", "https://a.acme.com/", "seed"))
        summary = orch.run_recon(include_active_scan=True)   # no approvals
        assert any("nuclei" in s for s in summary["needs_approval"])
        db.close()


def test_ingest_nuclei_creates_findings():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="acme"))
        orch = Orchestrator(db, eng, _policy())
        recs = [{"template_id": "cve-x", "name": "Thing", "severity": "high",
                 "matched_at": "https://a.acme.com/x"}]
        out = orch.ingest_nuclei(recs, reproduce_fn=lambda f: (True, "reproduced"))
        assert out[0]["status"] == "validated"
        db.close()


def test_sandbox_cmd_is_locked_down():
    cmd = sandbox.build_docker_cmd("kali:latest", ["nuclei", "-u", "https://a.acme.com"], "/tmp/ws")
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--cap-drop" in cmd and "--read-only" in cmd
    assert cmd[-3:] == ["nuclei", "-u", "https://a.acme.com"]


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

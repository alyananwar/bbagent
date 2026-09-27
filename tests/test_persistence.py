"""Regressions for the data-loss bugs: truncated tool output, a graph that only
reached disk at the end of a run, and a planner that never probed anything."""
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.db import DB
from bbagent.evidence import EvidenceStore
from bbagent.graph import Node, SurfaceGraph
from bbagent.models import (ActionClass, Engagement, ProgramPermissions, RuleKind,
                            ScopePolicy, ScopeRule)
from bbagent.orchestrator import Orchestrator
from bbagent.recon import parsers, planner, runner
from bbagent import toolrun


def _policy():
    return ScopePolicy(
        in_scope=[ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.acme.com"),
                  ScopeRule(RuleKind.DOMAIN, "acme.com")],
        permissions=ProgramPermissions(active_testing_allowed=True,
                                       automated_scanning_allowed=True))


def test_katana_output_is_not_truncated():
    """A big crawl used to be cut to the last 8000 chars before parsing."""
    urls = ["https://a.acme.com/page/%d" % i for i in range(2000)]
    raw = "\n".join(urls)
    assert len(raw) > 8000
    recs = parsers.parse_katana(raw)
    assert len(recs) == 2000

    with tempfile.TemporaryDirectory() as d:
        store = EvidenceStore(os.path.join(d, "ev"))
        run = toolrun.run("python3", ["-c", "print('\\n'.join('x'*200 for _ in range(200)))"],
                          "a.acme.com", ActionClass.B_LOW_ACTIVE, _policy(), store=store)
        assert run.exit_code == 0
        assert len(run.stdout) > 8000, "full stdout must survive for the parser"
        assert run.stdout_bytes == len(run.stdout)
        assert run.stdout_sha256 and os.path.exists(os.path.join(d, "ev", "objects",
                                                                 run.stdout_sha256))
        assert "stdout" not in run.to_dict(), "full body stays out of the DB row"


def test_graph_persists_after_every_step():
    """Recon that dies partway must not lose what it already discovered."""
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="acme"))
        orch = Orchestrator(db, eng, _policy())
        orch.graph.add(Node("subdomain", "seed.acme.com", "test"))
        orch.run_recon(max_steps=2)
        saved = db.load_graph(eng)
        assert saved is not None, "graph must be in the DB, not only in a scratch file"
        assert "subdomain::seed.acme.com" in saved["nodes"]
        db.close()


def test_graph_survives_reload():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="acme"))
        g = SurfaceGraph()
        runner.fold(g, "katana", [{"url": "https://a.acme.com/api/orders/7"}], "https://a.acme.com/")
        db.save_graph(eng, g.to_dict())
        again = SurfaceGraph.from_dict(db.load_graph(eng))
        assert [n.value for n in again.by_type("endpoint")] == ["https://a.acme.com/api/orders/7"]
        db.close()


def test_httpx_is_planned_even_after_dnsx_adds_ip_children():
    """The old check was `not graph.children(host)`, and dnsx attaches IPs as
    children -- so httpx never ran and the pipeline starved."""
    g = SurfaceGraph()
    runner.fold(g, "subfinder", [{"subdomain": "a.acme.com"}], "acme.com")
    runner.fold(g, "dnsx", [{"host": "a.acme.com", "ips": ["1.2.3.4"]}], "acme.com")
    assert any(s.tool == "httpx" and s.target == "a.acme.com" for s in planner.expand_plan(g))
    runner.mark_probed(g, "httpx", "a.acme.com")
    assert not any(s.tool == "httpx" and s.target == "a.acme.com"
                   for s in planner.expand_plan(g))


def test_wrong_binary_on_path_is_diagnosed_not_run():
    """pip's httpx CLI shadowing projectdiscovery httpx exits 0 and produces junk."""
    msg = toolrun.wrong_binary("python3", "projectdiscovery")
    assert msg and "does not look like the expected tool" in msg
    assert toolrun.wrong_binary("python3", "python") is None
    run = toolrun.run("python3", ["-c", "print(1)"], "a.acme.com", ActionClass.B_LOW_ACTIVE,
                      _policy(), identity_hint="projectdiscovery")
    assert run.exit_code is None and "does not look like" in run.stderr_ref
    assert not run.stdout, "a misidentified binary must not be executed"


def test_timeout_keeps_partial_output():
    run = toolrun.run("python3",
                      ["-c", "import sys,time;print('early');sys.stdout.flush();time.sleep(5)"],
                      "a.acme.com", ActionClass.B_LOW_ACTIVE, _policy(), timeout=1)
    assert "timeout" in run.stderr_ref
    assert "early" in run.stdout, "partial output is data, not garbage"


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

"""End-to-end: the loop must keep working past a clean scanner pass.

Runs against benchmarks/mock_app.py, which is deliberately boring to a template
scanner and broken only in a way that requires comparing two identities.
"""
import json
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "benchmarks"))

import mock_app
from bbagent.db import DB
from bbagent.evidence import EvidenceStore
from bbagent.graph import Node
from bbagent.models import (Engagement, ProgramPermissions, RuleKind, ScopePolicy, ScopeRule)
from bbagent.research.appmodel import Account
from bbagent.research.coverage import Budget
from bbagent.research.hypothesis import Category, HypothesisStatus
from bbagent.research.loop import ResearchLoop
from bbagent.research.state import ResearchState, is_terminal

_SRV, _PORT = mock_app.serve()
BASE = "http://127.0.0.1:%d" % _PORT


def _policy():
    return ScopePolicy(
        in_scope=[ScopeRule(RuleKind.URL, BASE + "/", source="benchmark")],
        permissions=ProgramPermissions(active_testing_allowed=True,
                                       automated_scanning_allowed=True,
                                       rate_limit_rps=50))


def _loop(d, seed=True, accounts=True):
    db = DB(os.path.join(d, "t.db"))
    eng = db.add_engagement(Engagement(program="mock", status="scope_confirmed"))
    store = EvidenceStore(os.path.join(d, "ev"))
    loop = ResearchLoop(db, eng, _policy(), store=store,
                        budget=Budget(max_tool_calls=60, max_investigations=40,
                                      max_seconds=120))
    if seed:
        # Start past RECON: these tests must not shell out to real recon tools.
        # The live end-to-end crawl is benchmarks/run_benchmark.py.
        db.set_research_state(eng, ResearchState.APPLICATION_MODELING.value)
        loop.state = ResearchState.APPLICATION_MODELING
        # stand in for the crawl: the endpoints katana would have found
        loop.graph.add(Node("url", BASE + "/", "seed"))
        loop.graph.add(Node("endpoint", BASE + "/api/v2/orders/1042", "seed"))
        loop.graph.add(Node("endpoint", BASE + "/admin/users/7", "seed"))
        loop.graph.add(Node("endpoint", BASE + "/health", "seed"))
        db.save_graph(eng, loop.graph.to_dict())
    if accounts:
        os.environ["BB_TOKEN_A"] = mock_app.TOKEN_A
        os.environ["BB_TOKEN_B"] = mock_app.TOKEN_B
        loop.add_account(Account("A", role="user", token_ref="Authorization=env:BB_TOKEN_A",
                                 identity="alice", owns=["1042"],
                                 auth_state="credentials_provided"))
        loop.add_account(Account("B", role="user", token_ref="Authorization=env:BB_TOKEN_B",
                                 identity="bob", owns=["1043"],
                                 auth_state="credentials_provided"))
    return db, eng, loop


def test_loop_reaches_a_validated_authorization_finding_with_zero_scanner_hits():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        summary = loop.run()

        assert not summary["recon"].get("nuclei_hits"), "no template hits on this app"
        assert not summary["recon"], "this test starts after the scanner phase"
        assert is_terminal(ResearchState(summary["state"])), summary["state"]
        assert summary["state"] != "halted_unauthorized"

        findings = [json.loads(f["data"]) for f in db.list_findings(eng)]
        authz = [f for f in findings if f["vuln_class"] == "authorization"]
        assert authz, "loop should reach the cross-account authorization bug: %s" % summary["coverage"]
        f = authz[0]
        assert "1042" in f["endpoint"]
        assert f["status"] in ("validated", "draft")
        assert f["steps"] and "identity" in f["steps"]
        assert f["impact"] == "", "impact is never invented"
        assert f["evidence"], "finding carries recorded responses"
        db.close()


def test_loop_rejects_the_endpoint_that_enforces_its_boundary():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.run()
        admin = [h for h in loop.queue.all() if "/admin/users/7" in h.target]
        assert admin, "admin endpoint should have been hypothesized about"
        assert any(h.status == HypothesisStatus.REJECTED for h in admin)
        assert any("role separation holds" in h.learned or "requires authentication" in h.learned
                   for h in admin), [h.learned for h in admin]
        db.close()


def test_scanner_noise_never_becomes_a_finding():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        # what nuclei actually returns against this app: informational noise
        loop.model = loop.model or None
        from bbagent.research import gain
        records = [{"template_id": "http-missing-security-headers", "severity": "info",
                    "matched_at": BASE + "/"}] * 11
        loop.run()
        before = len(db.list_findings(eng))
        assert not gain.from_scanner(records, loop.model), "info severity is not a lead"
        assert len(db.list_findings(eng)) == before
        db.close()


def test_finding_lists_identical_evidence_once():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.run()
        for f in db.list_findings(eng):
            ev = json.loads(f["data"])["evidence"]
            refs = [e["ref"] for e in ev]
            assert len(refs) == len(set(refs)), refs
        db.close()


def test_public_endpoint_is_not_reported():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.run()
        findings = [json.loads(f["data"]) for f in db.list_findings(eng)]
        assert not [f for f in findings if "/health" in f["endpoint"]], \
            "a public health endpoint is not a finding"
        db.close()


def test_missing_second_account_becomes_a_blocker_not_an_exit():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d, accounts=False)
        summary = loop.run()
        kinds = [b["kind"] for b in summary["blockers"]]
        assert "account_needed" in kinds, summary["blockers"]
        parked = loop.queue.by_status(HypothesisStatus.REQUIRES_HUMAN_ACTION)
        assert parked, "work parks on the human instead of disappearing"
        assert summary["state"] in ("hypotheses_exhausted", "budget_exhausted")
        db.close()


def test_resolving_a_blocker_resumes_without_manual_state_surgery():
    """A parked engagement used to persist a terminal state, so `bbagent resolve`
    followed by `bbagent research` did nothing forever."""
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d, accounts=False)
        first = loop.run()
        assert first["state"] == "hypotheses_exhausted"
        assert loop.queue.by_status(HypothesisStatus.REQUIRES_HUMAN_ACTION)

        # exactly what cmd_resolve does: reopen the hypothesis, nothing else
        from bbagent.research.hypothesis import replace
        parked = loop.queue.by_status(HypothesisStatus.REQUIRES_HUMAN_ACTION)[0]
        loop.queue.update(replace(parked, status=HypothesisStatus.UNTESTED))

        os.environ["BB_TOKEN_A"] = mock_app.TOKEN_A
        os.environ["BB_TOKEN_B"] = mock_app.TOKEN_B
        loop2 = ResearchLoop(db, eng, _policy(), store=loop.store,
                             budget=Budget(max_tool_calls=60, max_investigations=40,
                                           max_seconds=120))
        assert loop2.state.value != "hypotheses_exhausted", \
            "a resolved blocker must take the engagement out of a terminal state"
        loop2.add_account(Account("A", role="user", token_ref="Authorization=env:BB_TOKEN_A",
                                  identity="alice", owns=["1042"],
                                  auth_state="credentials_provided"))
        loop2.add_account(Account("B", role="user", token_ref="Authorization=env:BB_TOKEN_B",
                                  identity="bob", owns=["1043"],
                                  auth_state="credentials_provided"))
        second = loop2.run()
        assert second["iterations"] > 0, "the loop must actually run again"
        assert db.list_findings(eng), "resumed research produced a result"
        db.close()


def test_research_log_shows_reasoning_before_each_action():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.run()
        rendered = loop.log.render()
        assert "reasoning before acting" in rendered
        assert "known:" in rendered and "missing:" in rendered
        assert "investigation result" in rendered
        assert "state -> hypothesis_generated" in rendered
        db.close()


def test_out_of_scope_target_is_never_probed():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.graph.add(Node("endpoint", "http://127.0.0.1:59999/api/orders/1", "seed"))
        loop.run()
        probed = [json.loads(r["data"])["target"] for r in
                  db.conn.execute("SELECT data FROM tool_runs WHERE engagement_id=?",
                                  (eng,)).fetchall()]
        assert not any("59999" in t for t in probed)
        findings = [json.loads(f["data"]) for f in db.list_findings(eng)]
        assert not [f for f in findings if "59999" in f["endpoint"]]
        db.close()


def test_budget_exhaustion_is_a_clean_stop():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng = db.add_engagement(Engagement(program="mock", status="scope_confirmed"))
        loop = ResearchLoop(db, eng, _policy(),
                            budget=Budget(max_tool_calls=1, max_investigations=1,
                                          max_seconds=120))
        loop.budget.spend_investigation(1)
        summary = loop.run()
        assert summary["state"] == "budget_exhausted"
        db.close()


def test_research_report_shows_rejections_and_evidence():
    with tempfile.TemporaryDirectory() as d:
        db, eng, loop = _loop(d)
        loop.run()
        from bbagent.research import report as research_report
        text = research_report.render(
            program="mock", state=loop.state.value, hypotheses=loop.queue.all(),
            findings=[json.loads(f["data"]) for f in db.list_findings(eng)],
            blockers=loop.blockers.open(), surface=loop.surface_counts(),
            budget=loop.budget, log_tail=loop.log.render(limit=5))
        assert "Hypotheses tested and rejected" in text
        assert "learned:" in text
        assert "RESEARCH COVERAGE" in text
        assert "_not assessed; a human writes impact_" in text, "impact is never invented"
        assert "sha256" in text, "validated findings cite recorded evidence"
        db.close()


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

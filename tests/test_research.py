"""The research layer: state machine, hypothesis queue, app model, coverage,
blockers, differential analysis, and the property this refactor is about --
zero scanner findings does NOT end the engagement."""
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.db import DB
from bbagent.models import (Engagement, ProgramPermissions, RuleKind, ScopePolicy,
                            ScopeRule)
from bbagent.graph import Node, SurfaceGraph
from bbagent.research import differential as D
from bbagent.research import gain
from bbagent.research.appmodel import Account, AppModel, classify_path, infer_endpoint, from_graph
from bbagent.research.blockers import BlockerKind, BlockerQueue
from bbagent.research.coverage import Budget, dimension_coverage, render
from bbagent.research.hypothesis import (Category, Hypothesis, HypothesisQueue,
                                         HypothesisStatus, make_id, replace)
from bbagent.research.log import ResearchLog
from bbagent.research.probe import Observation, account_headers
from bbagent.research.state import IllegalTransition, ResearchState, advance, is_terminal


def _policy(active=True):
    return ScopePolicy(
        in_scope=[ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.acme.com"),
                  ScopeRule(RuleKind.DOMAIN, "acme.com")],
        permissions=ProgramPermissions(active_testing_allowed=active,
                                       automated_scanning_allowed=active))


def _db():
    d = tempfile.mkdtemp()
    db = DB(os.path.join(d, "t.db"))
    return db, db.add_engagement(Engagement(program="acme"))


# --- state machine ---------------------------------------------------------

def test_recon_leads_to_modeling_not_to_an_exit():
    assert advance(ResearchState.RECON, ResearchState.APPLICATION_MODELING)
    assert not is_terminal(ResearchState.RECON)
    assert not is_terminal(ResearchState.APPLICATION_MODELING)


def test_only_three_terminal_states():
    terminal = [s for s in ResearchState if is_terminal(s)]
    assert set(t.value for t in terminal) == {
        "budget_exhausted", "hypotheses_exhausted", "halted_unauthorized"}


def test_blocked_state_is_not_terminal_and_resumes():
    assert not is_terminal(ResearchState.BLOCKED_ON_RESEARCHER)
    assert advance(ResearchState.BLOCKED_ON_RESEARCHER, ResearchState.INVESTIGATION)


def test_illegal_transition_raises():
    try:
        advance(ResearchState.RECON, ResearchState.VALIDATION)
    except IllegalTransition:
        return
    raise AssertionError("recon -> validation should not be legal")


# --- hypothesis queue ------------------------------------------------------

def test_hypothesis_queue_persists_and_prioritizes():
    db, eng = _db()
    q = HypothesisQueue(db, eng)
    q.add(Hypothesis(id="H-low", category=Category.API, target="u", reasoning="r",
                     expected_observation="e", priority=0.2))
    q.add(Hypothesis(id="H-high", category=Category.AUTHZ, target="u", reasoning="r",
                     expected_observation="e", priority=0.9))
    assert q.next().id == "H-high"
    # survives a fresh queue object over the same storage
    assert HypothesisQueue(db, eng).next().id == "H-high"
    db.close()


def test_rejected_hypothesis_keeps_what_it_taught():
    db, eng = _db()
    q = HypothesisQueue(db, eng)
    h = q.add(Hypothesis(id="H1", category=Category.AUTHZ, target="u", reasoning="r",
                         expected_observation="e"))
    q.update(replace(h, status=HypothesisStatus.REJECTED,
                     learned="endpoint enforces object ownership"))
    stored = HypothesisQueue(db, eng).all()[0]
    assert stored.status == HypothesisStatus.REJECTED
    assert "enforces object ownership" in stored.learned
    assert stored.id not in [x.id for x in q.open()], "closed work is not re-queued"
    db.close()


def test_hypothesis_out_of_attempts_is_not_retried_forever():
    db, eng = _db()
    q = HypothesisQueue(db, eng)
    h = q.add(Hypothesis(id="H1", category=Category.AUTHZ, target="u", reasoning="r",
                         expected_observation="e", status=HypothesisStatus.INVESTIGATING))
    q.update(replace(h, attempts=q.MAX_ATTEMPTS))
    assert q.open() == [] and q.next() is None
    assert [x.id for x in q.stuck()] == ["H1"]
    db.close()


def test_hypothesis_ids_are_stable_and_category_distinct():
    a = make_id(Category.AUTH, "https://x/u/1", "anonymous-read")
    b = make_id(Category.AUTHZ, "https://x/u/1", "anonymous-read")
    assert a == make_id(Category.AUTH, "https://X/u/1 ", "anonymous-read")
    assert a != b and a.startswith("H-authn") and b.startswith("H-authz")


# --- application model -----------------------------------------------------

def test_endpoint_is_modeled_as_object_role_and_state():
    ep = infer_endpoint("https://a.acme.com/admin/orders/1042?expand=1", "POST")
    assert ep.object_type == "orders" and ep.object_id == "1042"
    assert ep.requires_role == "privileged" and ep.changes_state is True
    assert ep.params == ["expand"]


def test_classify_path_handles_uuid_and_api_versions():
    obj, oid, _ = classify_path("https://x/api/v2/users/3f1b2c44-5d6e-7a8b-9c0d-1e2f3a4b5c6d")
    assert obj == "users" and oid.startswith("3f1b2c44")


def test_authorization_matrix_and_gaps():
    m = AppModel()
    ep = m.add_endpoint(infer_endpoint("https://a.acme.com/api/orders/7"))
    assert len(m.unknown_authorization()) == 1
    m.observe("user", ep.key, "denied")
    assert m.access("user", ep.key) == "denied"
    assert m.unknown_authorization() == []


def test_model_keeps_what_investigations_taught_it():
    m = AppModel()
    ep = m.add_endpoint(infer_endpoint("https://a.acme.com/api/orders/7"))
    m.learn(ep.key, "enforces object ownership for role user")
    m.learn(ep.key, "enforces object ownership for role user")      # idempotent
    assert m.endpoints[ep.key].notes == ["enforces object ownership for role user"]
    assert AppModel.from_dict(m.to_dict()).endpoints[ep.key].notes == m.endpoints[ep.key].notes


def test_model_round_trips_and_folds_from_graph():
    g = SurfaceGraph()
    g.add(Node("endpoint", "https://a.acme.com/api/orders/7", "recon:katana"))
    m = from_graph(g)
    assert "GET https://a.acme.com/api/orders/7" in m.endpoints
    again = AppModel.from_dict(m.to_dict())
    assert again.endpoints.keys() == m.endpoints.keys()
    assert "orders" in again.resources


def test_account_without_token_is_not_usable():
    assert not Account("A").usable
    assert Account("A", token_ref="Authorization=env:X",
                   auth_state="credentials_provided").usable


def test_secrets_are_referenced_not_stored():
    a = Account("B", token_ref="Authorization=env:BB_TOKEN_B",
                auth_state="credentials_provided")
    assert "env:" in a.to_dict()["token_ref"]
    os.environ.pop("BB_TOKEN_B", None)
    headers, missing = account_headers(a)
    assert headers == {} and "BB_TOKEN_B" in missing
    os.environ["BB_TOKEN_B"] = "secret-value"
    headers, missing = account_headers(a)
    assert headers["Authorization"] == "secret-value" and not missing
    os.environ.pop("BB_TOKEN_B")


# --- hypothesis generation from the model ---------------------------------

def test_generation_needs_no_scanner_hits():
    m = AppModel()
    m.add_endpoint(infer_endpoint("https://a.acme.com/api/v2/orders/1042"))
    m.add_endpoint(infer_endpoint("https://a.acme.com/admin/users/7"))
    hs = gain.generate(m)
    cats = {h.category for h in hs}
    assert Category.AUTHZ in cats and Category.AUTH in cats and Category.API in cats
    assert all(h.expected_observation for h in hs)
    assert hs == sorted(hs, key=lambda h: -h.priority)


def test_state_changing_hypotheses_require_approval_class():
    m = AppModel()
    m.add_endpoint(infer_endpoint("https://a.acme.com/cart/update?qty=1&price=5", "POST"))
    logic = [h for h in gain.generate(m) if h.category == Category.BUSINESS_LOGIC]
    assert logic and logic[0].authorization == "D"


def test_reasoning_step_names_what_is_missing():
    m = AppModel()
    m.add_endpoint(infer_endpoint("https://a.acme.com/api/orders/1"))
    step = gain.reason(m, gain.generate(m)[0])
    assert any("second researcher-controlled account" in x for x in step.missing)
    assert step.evidence_path and step.hypothesis_id


def test_scanner_hits_inform_the_model_and_only_medium_plus_become_leads():
    """11 info-severity template matches are context, not 11 findings."""
    m = AppModel()
    m.add_endpoint(infer_endpoint("http://a.acme.com/"))
    records = [{"template_id": "http-missing-security-headers", "severity": "info",
                "matched_at": "http://a.acme.com/"},
               {"template_id": "tech-detect", "severity": "info",
                "matched_at": "http://a.acme.com/"},
               {"template_id": "some-real-thing", "severity": "high",
                "matched_at": "http://a.acme.com/"}]
    hyps = gain.from_scanner(records, m)
    assert [h.category for h in hyps] == [Category.CONFIG]
    assert hyps[0].status == HypothesisStatus.UNTESTED, "a scanner hit still has to be proved"
    notes = m.endpoints["GET http://a.acme.com/"].notes
    assert len(notes) == 3 and any("tech-detect" in n for n in notes)


# --- differential ----------------------------------------------------------

def _obs(status, sha="", body="", account="A"):
    return Observation(url="https://a.acme.com/api/orders/7", method="GET", account=account,
                       status=status, sha256=sha, length=len(body), snippet=body)


def test_same_object_reached_by_two_identities_is_flagged():
    body = '{"id":7,"owner_id":"user-a"}'
    d = D.compare(_obs(200, "h1", body, "A"), _obs(200, "h1", body, "B"))
    assert d.same_object and d.security_relevant
    assert ".id=7" in d.shared_ids


def test_enforced_boundary_is_not_flagged():
    d = D.compare(_obs(200, "h1", '{"id":7}', "A"), _obs(403, account="B"))
    assert not d.security_relevant and "enforced" in d.interpretation


def test_inverted_access_is_flagged():
    d = D.compare(_obs(403, account="A"), _obs(200, "h2", '{"id":7}', "B"))
    assert d.security_relevant and "inverted" in d.interpretation


def test_permission_sets_compare_structurally():
    out = D.compare_permission_sets({"GET /admin": "authorized"},
                                    {"GET /admin": "authorized"})
    assert out["both_authorized"] == ["GET /admin"]


def test_raw_secret_is_refused_before_it_can_be_stored():
    """A pasted token (or a missing `env:`) must never reach the app_models table."""
    from bbagent.research.appmodel import UnsafeTokenRef, check_token_ref
    for bad in ("Authorization: Bearer sk-live-ABCDEF", "sk-live-ABCDEF",
                "Authorization=sk-live-ABCDEF", "Authorization=env:", "=env:X"):
        try:
            Account("B", token_ref=bad)
        except UnsafeTokenRef as e:
            assert "sk-live-ABCDEF" not in str(e) or str(e).count("sk-live-ABCDEF") <= 1
            continue
        raise AssertionError("token_ref %r should have been refused" % bad)
    Account("B", token_ref="Cookie=env:BB_SESSION")        # the only accepted shape
    Account("B", token_ref="")                             # anonymous is fine
    check_token_ref("X-Api-Key=env:BB_KEY2")


def test_app_model_never_persists_a_raw_secret():
    db, eng = _db()
    m = AppModel()
    m.add_account(Account("A", token_ref="Authorization=env:BB_TOKEN_A",
                          auth_state="credentials_provided"))
    db.save_app_model(eng, m.to_dict())
    raw = db.conn.execute("SELECT data FROM app_models WHERE engagement_id=?",
                          (eng,)).fetchone()["data"]
    assert "env:BB_TOKEN_A" in raw and "Bearer" not in raw
    db.close()


def test_non_web_schemes_are_never_in_scope_or_probed():
    from bbagent.research.probe import NotAuthorized, Prober
    pol = ScopePolicy(in_scope=[ScopeRule(RuleKind.DOMAIN, "acme.com"),
                                ScopeRule(RuleKind.CIDR, "10.0.0.0/8")],
                      permissions=ProgramPermissions(active_testing_allowed=True))
    from bbagent import scope as scope_mod
    for bad in ("file://acme.com/etc/passwd", "ftp://acme.com/x", "gopher://10.0.0.5/"):
        assert scope_mod.evaluate(bad, pol).decision.value == "unknown", bad
    assert scope_mod.evaluate("https://acme.com/x", pol).decision.value == "in_scope"
    try:
        Prober(pol).request("ftp://acme.com/x")
    except NotAuthorized as e:
        assert "http(s)" in e.reason
        return
    raise AssertionError("prober must refuse a non-http scheme")


def test_repo_rules_still_match_after_the_scheme_guard():
    pol = ScopePolicy(in_scope=[ScopeRule(RuleKind.REPO, "https://github.com/acme/app")])
    from bbagent import scope as scope_mod
    assert scope_mod.evaluate("https://github.com/acme/app", pol).decision.value == "in_scope"


def test_probe_does_not_follow_redirects_out_of_scope():
    """urllib follows 3xx by default, which would carry our auth header to whatever
    host the target names."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from bbagent.research.probe import Prober

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):                    # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://out-of-scope.example.test/x")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    pol = ScopePolicy(in_scope=[ScopeRule(RuleKind.URL, "http://127.0.0.1:%d/" % port)],
                      permissions=ProgramPermissions(active_testing_allowed=True,
                                                     rate_limit_rps=50))
    obs = Prober(pol).request("http://127.0.0.1:%d/go" % port)
    srv.shutdown()
    assert obs.status == 302 and "out-of-scope.example.test" in obs.redirect_to
    assert not obs.error


# --- blockers --------------------------------------------------------------

def test_blocker_is_raised_once_and_resolves():
    db, eng = _db()
    bq = BlockerQueue(db, eng)
    b1 = bq.raise_blocker(BlockerKind.ACCOUNT_NEEDED, "second account", "cannot compare",
                          how_to_provide="bbagent account add B")
    b2 = bq.raise_blocker(BlockerKind.ACCOUNT_NEEDED, "second account", "cannot compare")
    assert b1.id == b2.id and len(bq.open()) == 1
    bq.resolve(b1.id, "account B provided")
    assert bq.open() == [] and bq.all()[0].resolution == "account B provided"
    db.close()


# --- coverage and budget ---------------------------------------------------

def test_coverage_reports_untouched_dimensions_honestly():
    hs = [Hypothesis(id="H1", category=Category.AUTHZ, target="u", reasoning="r",
                     expected_observation="e", status=HypothesisStatus.REJECTED)]
    cov = dimension_coverage(hs)
    assert cov["authorization"]["tested"] == 1 and cov["authorization"]["fraction"] == 1.0
    assert cov["business_logic"]["hypotheses"] == 0
    out = render(hs, Budget(max_tool_calls=5))
    assert "no hypotheses generated" in out and "BUDGET" in out


def test_budget_exhausts_on_calls():
    b = Budget(max_tool_calls=2, max_seconds=999, max_investigations=999)
    assert not b.exhausted()
    b.spend_tool_call(2)
    assert b.exhausted() and b.remaining()["tool_calls"] == 0


# --- research log ----------------------------------------------------------

def test_research_log_is_chronological_and_records_authorization():
    db, eng = _db()
    log = ResearchLog(db, eng)
    log.record("planner", "generated hypotheses", result="3 new", state="hypothesis_generated")
    log.record("investigator", "probe", hypothesis_id="H1",
               authorization="allow: in-scope, program permits", result="403")
    entries = log.entries()
    assert [e.agent for e in entries] == ["planner", "investigator"]
    assert "in-scope" in log.render()
    db.close()


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

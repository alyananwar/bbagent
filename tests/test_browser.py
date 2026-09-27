"""Browser to API correlation: what a logged-in session reveals that a crawler can't,
and the guarantee that credentials never survive the import."""
import json
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.db import DB
from bbagent.models import Engagement, ProgramPermissions, RuleKind, ScopePolicy, ScopeRule
from bbagent.research import browser, gain
from bbagent.research.appmodel import AppModel
from bbagent.research.hypothesis import Category

SECRET = "Bearer api-abcdef0123456789"
COOKIE = "ldso=super-secret-session-value"

HAR = json.dumps({"log": {"entries": [
    {"request": {"method": "GET", "url": "https://app.acme.com/api/v2/projects/default",
                 "headers": [{"name": "Cookie", "value": COOKIE}]},
     "response": {"status": 200, "content": {"mimeType": "application/json"}}},
    {"request": {"method": "POST", "url": "https://app.acme.com/api/v2/flags/default",
                 "headers": [{"name": "Authorization", "value": SECRET}],
                 "postData": {"text": '{"key":"new-flag","name":"New","temporary":true}'}},
     "response": {"status": 201, "content": {"mimeType": "application/json"}}},
    {"request": {"method": "GET", "url": "https://app.acme.com/static/main.js", "headers": []},
     "response": {"status": 200, "content": {"mimeType": "application/javascript"}}},
]}})

RECORDS = json.dumps([
    {"url": "https://app.acme.com/api/v2/members/3011", "method": "GET", "status": 200,
     "requestHeaders": {"Authorization": SECRET}, "responseType": "application/json"},
    {"url": "https://app.acme.com/favicon.ico", "method": "GET", "status": 200,
     "requestHeaders": {}, "responseType": "image/x-icon"},
])


def test_har_import_keeps_api_calls_and_drops_static():
    reqs = browser.from_har(HAR, workflow="create feature flag")
    assert [r.method for r in reqs] == ["GET", "POST"], "static assets are not API surface"
    assert all(r.workflow == "create feature flag" for r in reqs)


def test_credentials_never_survive_the_import():
    reqs = browser.from_har(HAR, workflow="create feature flag")
    blob = json.dumps([r.to_dict() for r in reqs])
    assert SECRET not in blob and "api-abcdef0123456789" not in blob
    assert COOKIE not in blob and "super-secret-session-value" not in blob
    # what IS kept is the classification and the header name
    kinds = {r.auth_kind for r in reqs}
    assert kinds == {"cookie", "bearer"}
    assert {r.auth_header for r in reqs} == {"Cookie", "Authorization"}


def test_redact_headers_masks_every_secret_header():
    out = browser.redact_headers({"Authorization": SECRET, "Cookie": COOKIE,
                                  "X-Api-Key": "k", "Accept": "application/json"})
    assert out["Authorization"] == "[redacted]" and out["Cookie"] == "[redacted]"
    assert out["X-Api-Key"] == "[redacted]"
    assert out["Accept"] == "application/json", "non-secret headers are kept"


def test_request_body_keys_are_kept_but_not_values():
    reqs = browser.from_har(HAR)
    post = [r for r in reqs if r.method == "POST"][0]
    assert post.request_body_keys == ["key", "name", "temporary"]
    assert "new-flag" not in json.dumps(post.to_dict()), "body values are not stored"


def test_fold_models_objects_and_records_the_workflow():
    m = AppModel()
    browser.fold(m, browser.from_har(HAR, workflow="create feature flag"))
    assert "GET https://app.acme.com/api/v2/projects/default" in m.endpoints
    ep = m.endpoints["POST https://app.acme.com/api/v2/flags/default"]
    assert ep.changes_state and "temporary" in ep.params
    assert any("create feature flag" in n for n in ep.notes)
    # a 2xx from an authenticated session is an observed authorization outcome
    assert m.access("browser_session",
                    "GET https://app.acme.com/api/v2/projects/default") == "authorized"


def test_records_shape_is_supported():
    reqs = browser.from_records(json.loads(RECORDS), workflow="open member page")
    assert len(reqs) == 1 and reqs[0].url.endswith("/members/3011")
    m = AppModel()
    browser.fold(m, reqs)
    assert m.endpoints["GET https://app.acme.com/api/v2/members/3011"].object_id == "3011"


def test_browser_hypotheses_need_a_sequence_a_crawler_cannot_see():
    reqs = browser.from_har(HAR, workflow="create feature flag")
    hyps = gain.from_browser(reqs, AppModel())
    flow = [h for h in hyps if h.category == Category.BROWSER_WORKFLOW]
    assert flow, "a multi-step flow ending in a write should raise a direct-invocation question"
    assert flow[0].authorization == "D", "state-changing tests are never auto-authorized"
    authz = [h for h in hyps if h.category == Category.AUTHZ]
    assert authz and "session cookie" in authz[0].reasoning


def test_capture_is_scope_gated_at_import():
    """A stray tab must not widen the engagement."""
    from bbagent import scope as scope_mod
    pol = ScopePolicy(in_scope=[ScopeRule(RuleKind.DOMAIN, "app.acme.com")],
                      permissions=ProgramPermissions(active_testing_allowed=True))
    mixed = browser.from_records([
        {"url": "https://app.acme.com/api/v2/projects", "method": "GET", "status": 200,
         "responseType": "application/json"},
        {"url": "https://tracker.example.net/api/collect", "method": "POST", "status": 200,
         "responseType": "application/json"},
    ])
    kept = [r for r in mixed if scope_mod.evaluate(r.url, pol).decision.value == "in_scope"]
    assert [r.url for r in kept] == ["https://app.acme.com/api/v2/projects"]


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

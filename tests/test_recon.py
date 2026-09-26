import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import RuleKind, ScopePolicy, ScopeRule, ProgramPermissions
from bbagent.graph import SurfaceGraph, Node
from bbagent.recon import adapters, parsers, planner, runner


def test_parse_subfinder_plain():
    recs = parsers.parse_subfinder("a.acme.com\nb.acme.com\n\n")
    assert {r["subdomain"] for r in recs} == {"a.acme.com", "b.acme.com"}


def test_parse_httpx_json():
    raw = '{"url":"https://a.acme.com","status_code":200,"tech":["nginx"],"title":"Home"}\n'
    recs = parsers.parse_httpx(raw)
    assert recs[0]["url"] == "https://a.acme.com"
    assert recs[0]["status"] == 200
    assert recs[0]["tech"] == ["nginx"]


def test_parse_nuclei_json():
    raw = '{"template-id":"cve-x","info":{"name":"Thing","severity":"high"},"matched-at":"https://a.acme.com/x"}\n'
    recs = parsers.parse_nuclei(raw)
    assert recs[0]["severity"] == "high"
    assert recs[0]["template_id"] == "cve-x"


def test_initial_plan_from_scope():
    pol = ScopePolicy(in_scope=[
        ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.acme.com"),
        ScopeRule(RuleKind.URL, "https://api.acme.com/v1/"),
    ])
    steps = planner.initial_plan(pol)
    tools = [s.tool for s in steps]
    assert "subfinder" in tools and "dnsx" in tools and "katana" in tools
    # subfinder targets the root domain, not the wildcard literal
    sf = [s for s in steps if s.tool == "subfinder"][0]
    assert sf.target == "acme.com"


def test_fold_builds_graph():
    g = SurfaceGraph()
    runner.fold(g, "subfinder", [{"subdomain": "a.acme.com"}, {"subdomain": "b.acme.com"}], "acme.com")
    assert len(g.by_type("subdomain")) == 2
    root = [n for n in g.by_type("domain")][0]
    assert len(g.children(root)) == 2


def test_expand_plan_probes_unprobed_hosts():
    g = SurfaceGraph()
    g.add(Node("subdomain", "a.acme.com", "recon:subfinder"))
    steps = planner.expand_plan(g)
    assert any(s.tool == "httpx" and s.target == "a.acme.com" for s in steps)



def test_active_adapter_injects_headers_and_rate():
    spec = adapters.get("httpx")
    args = spec.build_args("http://x", {"User-Agent": "ua (bugcrowd)"}, 10)
    assert "-H" in args and "User-Agent: ua (bugcrowd)" in args
    assert "-rl" in args and "10" in args


def test_passive_adapter_ignores_headers():
    args = adapters.get("subfinder").build_args("x.com", {"User-Agent": "ua"}, 10)
    assert "-H" not in args and "-rl" not in args


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

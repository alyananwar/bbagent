import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import RuleKind, ScopePolicy, ScopeRule, ScopeDecisionKind
from bbagent import scope


def _policy():
    return ScopePolicy(
        in_scope=[
            ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.example.com"),
            ScopeRule(RuleKind.DOMAIN, "example.com"),
            ScopeRule(RuleKind.URL, "https://api.example.com/v1/"),
            ScopeRule(RuleKind.CIDR, "10.0.0.0/24"),
        ],
        out_of_scope=[
            ScopeRule(RuleKind.DOMAIN, "admin.example.com"),
            ScopeRule(RuleKind.URL, "https://api.example.com/v1/internal/"),
        ],
    )


def test_wildcard_matches_subdomain():
    d = scope.evaluate("shop.example.com", _policy())
    assert d.decision == ScopeDecisionKind.IN_SCOPE, d


def test_wildcard_matches_deep_subdomain():
    d = scope.evaluate("a.b.example.com", _policy())
    assert d.decision == ScopeDecisionKind.IN_SCOPE, d


def test_apex_needs_explicit_rule():
    # apex is in scope only because we added an explicit DOMAIN rule
    d = scope.evaluate("example.com", _policy())
    assert d.decision == ScopeDecisionKind.IN_SCOPE, d


def test_out_of_scope_beats_in_scope():
    d = scope.evaluate("admin.example.com", _policy())
    assert d.decision == ScopeDecisionKind.OUT_OF_SCOPE, d


def test_unknown_domain():
    d = scope.evaluate("evil.other.com", _policy())
    assert d.decision == ScopeDecisionKind.UNKNOWN, d


def test_url_path_prefix_in_scope():
    d = scope.evaluate("https://api.example.com/v1/users?id=1", _policy())
    assert d.decision == ScopeDecisionKind.IN_SCOPE, d


def test_url_out_of_scope_path_wins():
    d = scope.evaluate("https://api.example.com/v1/internal/secrets", _policy())
    assert d.decision == ScopeDecisionKind.OUT_OF_SCOPE, d


def test_cidr_in_scope():
    d = scope.evaluate("10.0.0.55", _policy())
    assert d.decision == ScopeDecisionKind.IN_SCOPE, d


def test_ip_outside_cidr_unknown():
    d = scope.evaluate("10.0.1.5", _policy())
    assert d.decision == ScopeDecisionKind.UNKNOWN, d


def test_cidr_not_authorized_when_absent():
    pol = ScopePolicy(in_scope=[ScopeRule(RuleKind.DOMAIN, "example.com")])
    d = scope.evaluate("10.0.0.5", pol)
    assert d.decision == ScopeDecisionKind.UNKNOWN, d


def test_empty_target_unknown():
    d = scope.evaluate("", _policy())
    assert d.decision == ScopeDecisionKind.UNKNOWN, d



def test_url_root_rule_matches_bare_host():
    from bbagent.models import ScopePolicy as SP, ScopeRule as SR
    pol = SP(in_scope=[SR(RuleKind.URL, "https://www.example.com/")])
    assert scope.evaluate("www.example.com", pol).decision == ScopeDecisionKind.IN_SCOPE


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

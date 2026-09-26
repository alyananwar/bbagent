import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import RuleKind
from bbagent import program_intel, intake

BRIEF = """
Acme Bug Bounty Program

In scope:
- *.acme.com
- acme.com
- https://api.acme.com/v1/
- 203.0.113.0/24

Out of scope:
- admin.acme.com
- blog.acme.com

Rules:
Automated scanning is allowed at 5 requests per second.
Active testing is permitted. No denial of service. Social engineering is prohibited.
"""


def test_parses_in_scope():
    pol = program_intel.parse_brief(BRIEF)
    values = {r.value for r in pol.in_scope}
    assert "*.acme.com" in values
    assert "acme.com" in values
    assert "203.0.113.0/24" in values


def test_parses_out_of_scope():
    pol = program_intel.parse_brief(BRIEF)
    values = {r.value for r in pol.out_of_scope}
    assert "admin.acme.com" in values
    assert "blog.acme.com" in values


def test_classifies_kinds():
    pol = program_intel.parse_brief(BRIEF)
    kinds = {r.value: r.kind for r in pol.in_scope}
    assert kinds["*.acme.com"] == RuleKind.WILDCARD_DOMAIN
    assert kinds["203.0.113.0/24"] == RuleKind.CIDR


def test_detects_permissions():
    pol = program_intel.parse_brief(BRIEF)
    assert pol.permissions.automated_scanning_allowed is True
    assert pol.permissions.active_testing_allowed is True
    assert pol.permissions.rate_limit_rps == 5.0
    assert "denial of service" in pol.permissions.prohibited_techniques


def test_permissions_default_safe():
    pol = program_intel.parse_brief("In scope:\nexample.com")
    assert pol.permissions.automated_scanning_allowed is False
    assert pol.permissions.active_testing_allowed is False
    assert pol.permissions.production_testing_allowed is False


def test_intake_from_brief_sets_platform_and_status():
    eng = intake.from_brief(BRIEF, program_url="https://bugcrowd.com/acme")
    assert eng.platform == "bugcrowd"
    assert eng.program == "acme"
    assert eng.status == "awaiting_scope_confirmation"


def test_intake_from_targets():
    eng = intake.from_targets(["*.foo.com", "foo.com"])
    values = {r.value for r in eng.policy.in_scope}
    assert "*.foo.com" in values and "foo.com" in values



def test_parses_required_user_agent():
    pol = program_intel.parse_brief("In scope:\nx.com\nRules:\nInclude the string bugcrowd in the User-Agent.")
    assert "bugcrowd" in pol.permissions.required_headers.get("User-Agent", "")


def test_parses_required_custom_header():
    pol = program_intel.parse_brief("In scope:\nx.com\nRules:\nRequired header: X-Request-Purpose BugcrowdResearch")
    assert pol.permissions.required_headers.get("X-Request-Purpose") == "BugcrowdResearch"


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

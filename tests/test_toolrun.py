import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import ActionClass, ProgramPermissions, RuleKind, ScopePolicy, ScopeRule
from bbagent import toolrun


def _pol():
    return ScopePolicy(
        in_scope=[ScopeRule(RuleKind.DOMAIN, "acme.com")],
        out_of_scope=[ScopeRule(RuleKind.DOMAIN, "admin.acme.com")],
        permissions=ProgramPermissions(active_testing_allowed=True),
    )


def test_denied_target_never_runs():
    try:
        toolrun.run("echo", ["hi"], "admin.acme.com", ActionClass.B_LOW_ACTIVE, _pol())
        assert False, "should have raised ScopeViolation"
    except toolrun.ScopeViolation:
        pass


def test_unknown_target_denied():
    try:
        toolrun.run("echo", ["hi"], "unknown.org", ActionClass.B_LOW_ACTIVE, _pol())
        assert False, "should have raised ScopeViolation"
    except toolrun.ScopeViolation:
        pass


def test_security_test_requires_approval():
    try:
        toolrun.run("echo", ["hi"], "acme.com", ActionClass.C_SECURITY_TEST, _pol())
        assert False, "should have raised ApprovalRequired"
    except toolrun.ApprovalRequired:
        pass


def test_allowed_runs_or_reports_missing_tool():
    # in-scope + class B + active testing permitted => allowed; echo exists on macOS/linux
    rec = toolrun.run("echo", ["ok"], "acme.com", ActionClass.B_LOW_ACTIVE, _pol())
    assert rec.verdict == "allow"
    assert rec.exit_code == 0 or rec.stderr_ref == "tool not installed on PATH"


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

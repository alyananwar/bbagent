import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import ActionClass, ProgramPermissions, ScopeDecisionKind, ScopePolicy, Verdict
from bbagent import policy


def _perms(**kw):
    return ScopePolicy(permissions=ProgramPermissions(**kw))


def test_passive_always_allowed():
    v, _ = policy.decide(ActionClass.A_PASSIVE, ScopeDecisionKind.UNKNOWN, _perms())
    assert v == Verdict.ALLOW


def test_external_always_needs_approval():
    v, _ = policy.decide(ActionClass.E_EXTERNAL, ScopeDecisionKind.IN_SCOPE,
                         _perms(active_testing_allowed=True))
    assert v == Verdict.REQUIRE_APPROVAL


def test_out_of_scope_denied():
    v, _ = policy.decide(ActionClass.B_LOW_ACTIVE, ScopeDecisionKind.OUT_OF_SCOPE,
                         _perms(active_testing_allowed=True))
    assert v == Verdict.DENY


def test_unknown_denied_for_active():
    v, _ = policy.decide(ActionClass.B_LOW_ACTIVE, ScopeDecisionKind.UNKNOWN,
                         _perms(active_testing_allowed=True))
    assert v == Verdict.DENY


def test_low_active_allowed_when_permitted():
    v, _ = policy.decide(ActionClass.B_LOW_ACTIVE, ScopeDecisionKind.IN_SCOPE,
                         _perms(active_testing_allowed=True))
    assert v == Verdict.ALLOW


def test_low_active_needs_approval_when_not_permitted():
    v, _ = policy.decide(ActionClass.B_LOW_ACTIVE, ScopeDecisionKind.IN_SCOPE, _perms())
    assert v == Verdict.REQUIRE_APPROVAL


def test_security_test_always_needs_approval_even_when_permitted():
    v, _ = policy.decide(ActionClass.C_SECURITY_TEST, ScopeDecisionKind.IN_SCOPE,
                         _perms(active_testing_allowed=True, poc_allowed=True))
    assert v == Verdict.REQUIRE_APPROVAL


def test_impactful_denied_without_production_permission():
    v, _ = policy.decide(ActionClass.D_IMPACTFUL, ScopeDecisionKind.IN_SCOPE,
                         _perms(active_testing_allowed=True))
    assert v == Verdict.DENY


def test_impactful_needs_approval_when_production_permitted():
    v, _ = policy.decide(ActionClass.D_IMPACTFUL, ScopeDecisionKind.IN_SCOPE,
                         _perms(production_testing_allowed=True))
    assert v == Verdict.REQUIRE_APPROVAL


def test_technique_policy_converts_automation_into_a_manual_task():
    pol = ScopePolicy(permissions=ProgramPermissions(active_testing_allowed=True))
    verdict, reason = policy.technique_policy("template scan", pol)
    assert verdict == policy.MANUAL_ONLY and "by hand" in reason


def test_technique_policy_blocks_prohibited_techniques():
    pol = ScopePolicy(permissions=ProgramPermissions(
        active_testing_allowed=True, automated_scanning_allowed=True,
        prohibited_techniques=["denial of service"]))
    assert policy.technique_policy("denial of service", pol)[0] == policy.PROHIBITED
    assert policy.technique_policy("authorization probe", pol)[0] == policy.AUTOMATION_ALLOWED


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

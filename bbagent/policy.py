"""Policy / action-class engine.

Turns (scope decision + action class + program permissions) into a final
Verdict: ALLOW / DENY / REQUIRE_APPROVAL. Deterministic, no LLM.

Guiding rules from the spec:
  - Out-of-scope target -> always DENY.
  - Unknown target -> never auto-allowed (DENY for anything target-directed).
  - Class E (submit report, message staff, publish) -> always REQUIRE_APPROVAL.
  - Class D (impactful) -> default DENY, REQUIRE_APPROVAL only if program permits.
  - Class C (security testing) -> REQUIRE_APPROVAL unless program explicitly
    permits active testing AND (for PoC) poc_allowed.
  - Class B (low active) -> ALLOW only if active testing permitted, else approval.
  - Class A (passive) -> ALLOW; not target-directed, scope check skipped.
"""
from typing import Tuple

from .models import ActionClass, ScopeDecisionKind, ScopePolicy, Verdict


def decide(action_class: ActionClass,
           scope_decision: ScopeDecisionKind,
           policy: ScopePolicy) -> Tuple[Verdict, str]:
    perms = policy.permissions

    # Class A is offline / not aimed at a target.
    if action_class == ActionClass.A_PASSIVE:
        return Verdict.ALLOW, "passive action, no target authorization required"

    # External actions never run without a human, regardless of scope.
    if action_class == ActionClass.E_EXTERNAL:
        return Verdict.REQUIRE_APPROVAL, "external action always requires human approval"

    # Everything below is target-directed: scope governs first.
    if scope_decision == ScopeDecisionKind.OUT_OF_SCOPE:
        return Verdict.DENY, "target is out of scope"
    if scope_decision == ScopeDecisionKind.UNKNOWN:
        return Verdict.DENY, "target scope unknown; unknown is never auto-authorized"

    # In-scope from here.
    if action_class == ActionClass.B_LOW_ACTIVE:
        if perms.active_testing_allowed or perms.automated_scanning_allowed:
            return Verdict.ALLOW, "in-scope, program permits active/automated testing"
        return Verdict.REQUIRE_APPROVAL, "in-scope but program has not confirmed active testing"

    if action_class == ActionClass.C_SECURITY_TEST:
        if not perms.active_testing_allowed:
            return Verdict.REQUIRE_APPROVAL, "security testing needs explicit program authorization"
        return Verdict.REQUIRE_APPROVAL, "in-scope security testing requires human sign-off per run"

    if action_class == ActionClass.D_IMPACTFUL:
        if perms.production_testing_allowed:
            return Verdict.REQUIRE_APPROVAL, "impactful action permitted by program but needs human approval"
        return Verdict.DENY, "impactful action defaults to deny unless program permits"

    return Verdict.DENY, "unclassified action denied by default"

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

# Technique policy. Programs restrict HOW a thing may be done, not only whether:
# "no automated scanning" usually means a human may still test it by hand. We
# make that explicit instead of quietly ignoring it or quietly stopping.
AUTOMATION_ALLOWED = "automation_allowed"
MANUAL_ONLY = "manual_only"
PROHIBITED = "prohibited"

# techniques that are automation by nature
_AUTOMATED_TECHNIQUES = ("scan", "fuzz", "brute", "crawl", "spray", "enumerat", "flood")


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


def technique_policy(technique: str, policy: ScopePolicy) -> Tuple[str, str]:
    """Classify a named technique against the program's own rules.

    Returns (AUTOMATION_ALLOWED | MANUAL_ONLY | PROHIBITED, reason). A
    manual_only technique is not a dead end: callers convert it into a human
    task (a RESEARCHER_ACTION blocker) rather than either skipping it silently or
    running it anyway.
    """
    t = (technique or "").strip().lower()
    perms = policy.permissions
    for banned in perms.prohibited_techniques:
        b = banned.strip().lower()
        if b and (b in t or t in b):
            return PROHIBITED, "program prohibits %r" % banned
    looks_automated = any(k in t for k in _AUTOMATED_TECHNIQUES)
    if looks_automated and not perms.automated_scanning_allowed:
        return MANUAL_ONLY, ("%r is automated by nature and the program has not "
                             "permitted automated scanning; a human may still do it "
                             "by hand" % technique)
    if not perms.active_testing_allowed and not perms.automated_scanning_allowed:
        return MANUAL_ONLY, "program has not confirmed active testing; hand off to a human"
    return AUTOMATION_ALLOWED, "permitted by program rules"

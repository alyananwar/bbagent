"""Information-gain reasoning.

Before anything touches the target, the loop has to answer four questions in
writing: what do we know, what is missing, which hypothesis does this test, and
what is the lowest-impact way to get that evidence. The answers are recorded in
the research log, so a run can be read back as reasoning rather than as a list of
commands.

This is also where hypotheses come from. Generation is deterministic and derived
from the application model (objects, roles, state changes) -- an LLM can add to
the queue via agents/plan.py, but it is never required to make progress.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..models import ActionClass
from .appmodel import AppModel, EndpointModel
from .hypothesis import Category, Hypothesis, make_id

# Cheapest evidence first: a read as an unauthorized identity costs the target
# nothing and answers most authorization questions.
_EVIDENCE_LADDER = (
    "compare an existing authorized response against the same request made by "
    "another researcher-controlled identity (single GET, no state change)",
    "request the object as anonymous (single GET)",
    "read the endpoint's own error/response body for authorization hints",
    "state-changing request (requires explicit approval; last resort)",
)


@dataclass
class ReasoningStep:
    """The written justification for one investigation."""
    known: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    hypothesis_id: str = ""
    tests: str = ""
    evidence_path: str = ""
    authorization: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        return ("known: %s | missing: %s | tests %s: %s | evidence path: %s"
                % ("; ".join(self.known) or "-", "; ".join(self.missing) or "-",
                   self.hypothesis_id or "-", self.tests or "-", self.evidence_path or "-"))


def reason(model: AppModel, hypothesis: Optional[Hypothesis]) -> ReasoningStep:
    known = [
        "%d endpoints modeled" % len(model.endpoints),
        "%d object types" % len(model.resources),
        "roles with usable accounts: %s" % (", ".join(model.roles_with_accounts()) or "none"),
        "%d endpoints with an observed authorization outcome" % len(model.matrix),
    ]
    missing = []
    unknown = model.unknown_authorization()
    if unknown:
        missing.append("authorization outcome unknown for %d endpoints" % len(unknown))
    if len(model.usable_accounts()) < 2:
        missing.append("a second researcher-controlled account (cross-account "
                       "authorization cannot be tested with one identity)")
    if not model.object_scoped_endpoints():
        missing.append("no object-scoped endpoints seen yet (need deeper crawl or "
                       "an authenticated session to reveal object ids)")
    step = ReasoningStep(known=known, missing=missing)
    if hypothesis is not None:
        step.hypothesis_id = hypothesis.id
        step.tests = hypothesis.reasoning
        step.evidence_path = _EVIDENCE_LADDER[0] if hypothesis.authorization == "B" else _EVIDENCE_LADDER[3]
        step.authorization = "class %s required" % hypothesis.authorization
    return step


def _priority(base: float, ep: EndpointModel, model: AppModel) -> float:
    """Information gain estimate: unknown beats known, cheap beats impactful."""
    p = base
    if model.access("anonymous", ep.key) == "unknown":
        p += 0.1                                  # we know nothing here yet
    if ep.object_id:
        p += 0.1                                  # concrete object to compare
    if ep.changes_state:
        p -= 0.2                                  # costs the target something
    return round(max(0.05, min(0.99, p)), 2)


# scanner severities that are worth a hypothesis of their own. Everything below
# is context for the model (tech stack, missing headers), not a lead.
_ACTIONABLE_SEVERITY = ("medium", "high", "critical")


def from_scanner(records: List[Dict[str, Any]], model: AppModel) -> List[Hypothesis]:
    """Fold scanner output into research state.

    An info-severity template match is not a finding and not a lead: it is
    something the model should know about the target. Anything medium or above
    becomes a hypothesis that still has to be reproduced and argued for like any
    other -- a scanner saying so is not evidence on its own.
    """
    out: List[Hypothesis] = []
    for r in records:
        target = r.get("matched_at") or ""
        template = r.get("template_id") or "unknown-template"
        severity = (r.get("severity") or "").lower()
        note = "scanner matched %s (%s)" % (template, severity or "unrated")
        for key in ("GET %s" % target, "GET %s/" % target.rstrip("/")):
            if key in model.endpoints:
                model.learn(key, note)
                break
        if severity not in _ACTIONABLE_SEVERITY:
            continue
        out.append(Hypothesis(
            id=make_id(Category.CONFIG, target, template),
            category=Category.CONFIG, target=target,
            reasoning="scanner template %s matched at %s with severity %s; needs "
                      "independent reproduction before it counts as anything"
                      % (template, target, severity),
            expected_observation="the condition the template describes is reproducible "
                                 "by a single request",
            authorization=ActionClass.B_LOW_ACTIVE.value,
            experiment="anonymous_read",
            priority=0.55, evidence=[dict(r)]))
    return out


def generate(model: AppModel) -> List[Hypothesis]:
    """Derive testable hypotheses from the application model.

    Every one names the object and the role involved, so a rejection teaches the
    model something specific instead of just closing a ticket.
    """
    out: List[Hypothesis] = []
    accounts = model.usable_accounts()
    other_labels = [a.label for a in accounts]

    for ep in model.object_scoped_endpoints():
        # authorization: cross-account object access (IDOR / broken object level auth)
        if len(accounts) >= 2:
            reasoning = ("%s addresses object %s/%s directly; if the id is not checked "
                         "against the caller, identity %s can read identity %s's object"
                         % (ep.key, ep.object_type or "?", ep.object_id,
                            other_labels[1], other_labels[0]))
            out.append(Hypothesis(
                id=make_id(Category.AUTHZ, ep.url, "cross-account-read"),
                category=Category.AUTHZ, target=ep.url, reasoning=reasoning,
                expected_observation=("identity %s receives 2xx containing the same object "
                                      "ids as identity %s" % (other_labels[1], other_labels[0])),
                authorization=ActionClass.B_LOW_ACTIVE.value,
                experiment="cross_account", priority=_priority(0.75, ep, model)))
        else:
            out.append(Hypothesis(
                id=make_id(Category.AUTHZ, ep.url, "cross-account-read"),
                category=Category.AUTHZ, target=ep.url,
                reasoning=("%s addresses object %s/%s directly, so object-level "
                           "authorization is testable -- but a second identity is needed "
                           "to compare against" % (ep.key, ep.object_type or "?", ep.object_id)),
                expected_observation="a second identity receives 2xx for an object it does not own",
                authorization=ActionClass.B_LOW_ACTIVE.value,
                experiment="cross_account", priority=_priority(0.7, ep, model)))
        # auth: object reachable with no credentials at all
        out.append(Hypothesis(
            id=make_id(Category.AUTH, ep.url, "anonymous-read"),
            category=Category.AUTH, target=ep.url,
            reasoning="%s addresses a specific object; check whether it requires any "
                      "authentication at all" % ep.key,
            expected_observation="anonymous request returns 2xx with object data",
            authorization=ActionClass.B_LOW_ACTIVE.value,
            experiment="anonymous_read", priority=_priority(0.6, ep, model)))

    # authorization: privileged surface reached by an unprivileged identity
    for ep in model.privileged_endpoints():
        out.append(Hypothesis(
            id=make_id(Category.AUTHZ, ep.url, "role-separation"),
            category=Category.AUTHZ, target=ep.url,
            reasoning="%s looks administrative by path; check that a normal or anonymous "
                      "identity is refused" % ep.key,
            expected_observation="non-privileged identity receives 2xx instead of 401/403",
            authorization=ActionClass.B_LOW_ACTIVE.value,
            experiment="role_separation", priority=_priority(0.8, ep, model)))

    # api: version pivot -- an older version of the same path often lost its checks
    for ep in list(model.endpoints.values()):
        if "/v2" in ep.url or "/v3" in ep.url:
            alt = ep.url.replace("/v3", "/v1").replace("/v2", "/v1")
            out.append(Hypothesis(
                id=make_id(Category.API, alt, "version-pivot"),
                category=Category.API, target=alt,
                reasoning="%s exists; an older API version of the same resource often "
                          "survives with weaker authorization" % ep.url,
                expected_observation="the v1 path responds and returns the same object type",
                authorization=ActionClass.B_LOW_ACTIVE.value,
                experiment="anonymous_read", priority=_priority(0.5, ep, model)))

    # business logic: state-changing endpoints with value-ish parameters
    for ep in model.state_changing_endpoints():
        interesting = [p for p in ep.params
                       if p.lower() in ("amount", "price", "qty", "quantity", "total",
                                        "discount", "role", "is_admin", "status", "state")]
        if interesting:
            out.append(Hypothesis(
                id=make_id(Category.BUSINESS_LOGIC, ep.url, "|".join(interesting)),
                category=Category.BUSINESS_LOGIC, target=ep.url,
                reasoning="%s changes state and takes %s; server-side validation of those "
                          "values is worth checking" % (ep.key, ", ".join(interesting)),
                expected_observation="the server accepts a value the UI would not allow",
                # state change is impactful: never auto-authorized
                authorization=ActionClass.D_IMPACTFUL.value,
                experiment="value_tamper", priority=_priority(0.45, ep, model)))

    # dedup by id, keep the highest priority version
    best: Dict[str, Hypothesis] = {}
    for h in out:
        prev = best.get(h.id)
        if prev is None or h.priority > prev.priority:
            best[h.id] = h
    return sorted(best.values(), key=lambda h: -h.priority)

"""Run one hypothesis.

Each category has a specific, minimal experiment. Every experiment records what
it observed into the application model, so even a rejection leaves the model
better informed than before. Nothing here decides a finding: it returns evidence
plus a verdict of SUPPORTED / REJECTED / REQUIRES_HUMAN_ACTION.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..models import ActionClass
from .. import policy as policy_mod
from .appmodel import Account, AppModel
from .blockers import BlockerKind
from .differential import compare, outcome
from .hypothesis import Category, Hypothesis, HypothesisStatus
from .probe import NotAuthorized, Prober

ANON = Account(label="anonymous", role="anonymous", auth_state="none")


@dataclass
class BlockerRequest:
    kind: BlockerKind
    what_is_needed: str
    reasoning: str
    how_to_provide: str = ""


@dataclass
class Result:
    status: HypothesisStatus
    observed: str = ""
    learned: str = ""
    observations: List[Dict[str, Any]] = field(default_factory=list)
    diff: Optional[Dict[str, Any]] = None
    blocker: Optional[BlockerRequest] = None
    authorization: str = ""


def _record(model: AppModel, url: str, obs) -> None:
    """Fold an observation back into the authorization matrix."""
    key = "%s %s" % (obs.method, url)
    if key not in model.endpoints:
        from .appmodel import infer_endpoint
        model.add_endpoint(infer_endpoint(url, obs.method, "investigation", obs.status))
    role = "anonymous"
    acct = model.accounts.get(obs.account)
    if acct is not None:
        role = acct.role
    model.observe(role, key, outcome(obs))


def _probe(prober: Prober, url: str, account, approved: bool, out: List[Dict[str, Any]],
           model: AppModel) -> Tuple[Optional[Any], Optional[Result]]:
    """One gated request. Returns (observation, early_result_on_refusal)."""
    try:
        obs = prober.request(url, "GET", account=account, approved=approved)
    except NotAuthorized as e:
        return None, Result(
            status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
            observed="gate refused the probe: %s" % e.reason,
            authorization="%s: %s" % (e.verdict, e.reason),
            blocker=BlockerRequest(
                BlockerKind.PROGRAM_CLARIFICATION,
                "authorization to probe %s" % url,
                "the scope/policy gate returned %s (%s); research cannot proceed on "
                "this hypothesis without it" % (e.verdict, e.reason),
                "confirm the program permits this, then re-run with --approve-investigation"))
    out.append(obs.to_dict())
    if obs.error:
        return obs, None
    _record(model, url, obs)
    return obs, None


def investigate(h: Hypothesis, model: AppModel, prober: Prober,
                approved: bool = False) -> Result:
    """Run the experiment for one hypothesis."""
    technique = "%s probe" % h.category.value
    tpol, treason = policy_mod.technique_policy(technique, prober.policy)
    if tpol == policy_mod.PROHIBITED:
        return Result(status=HypothesisStatus.REJECTED,
                      observed="not attempted: %s" % treason,
                      learned="program rules forbid this technique; the question stays open "
                              "but is out of bounds for this engagement",
                      authorization="prohibited: %s" % treason)
    if tpol == policy_mod.MANUAL_ONLY:
        return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                      observed="converted to a human task: %s" % treason,
                      authorization="manual_only: %s" % treason,
                      blocker=BlockerRequest(
                          BlockerKind.MANUAL_ONLY_TECHNIQUE,
                          "manual test of %s (%s)" % (h.target, h.category.value),
                          treason,
                          "test by hand, then: bbagent resolve %s --note '<what you saw>'" % h.id))

    if h.authorization == ActionClass.D_IMPACTFUL.value and not approved:
        return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                      observed="state-changing test not attempted without approval",
                      authorization="class D requires explicit approval",
                      blocker=BlockerRequest(
                          BlockerKind.MANUAL_ONLY_TECHNIQUE,
                          "approval for a state-changing request to %s" % h.target,
                          h.reasoning,
                          "bbagent research --approve-investigation (or test by hand)"))

    obs_list: List[Dict[str, Any]] = []
    accounts = model.usable_accounts()

    experiment = h.experiment or _default_experiment(h)
    if experiment == "cross_account":
        return _cross_account(h, model, prober, approved, obs_list, accounts)
    if experiment == "role_separation":
        return _role_separation(h, model, prober, approved, obs_list, accounts)
    if experiment == "anonymous_read":
        return _anonymous_reach(h, model, prober, approved, obs_list)
    return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                  observed="no automated experiment defined for category %s" % h.category.value,
                  blocker=BlockerRequest(
                      BlockerKind.MANUAL_ONLY_TECHNIQUE,
                      "manual investigation of %s" % h.target, h.reasoning,
                      "bbagent resolve %s --note '<what you saw>'" % h.id))


def _default_experiment(h: Hypothesis) -> str:
    """Fallback for hypotheses from the LLM advisor, which has no experiment name."""
    if h.category == Category.AUTHZ:
        return "cross_account"
    if h.category in (Category.AUTH, Category.API, Category.INFO_DISCLOSURE):
        return "anonymous_read"
    return ""


def _cross_account(h, model, prober, approved, obs_list, accounts) -> Result:
    if len(accounts) < 2:
        return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                      observed="cannot compare identities: %d usable account(s)" % len(accounts),
                      learned="object-level authorization on %s is untested and stays open"
                              % h.target,
                      blocker=BlockerRequest(
                          BlockerKind.ACCOUNT_NEEDED,
                          "a second researcher-controlled account for %s" % h.target,
                          "comparing what two identities can reach is the only way to test "
                          "object-level authorization; with one identity a 2xx proves nothing",
                          "bbagent account add B --role user --token 'Authorization=env:BB_TOKEN_B'"))
    ep = model.endpoints.get("GET %s" % h.target)
    oid = ep.object_id if ep else ""
    owner = next((a for a in accounts if oid and oid in a.owns), accounts[0])
    other = next((a for a in accounts if a.label != owner.label), accounts[1])
    obs_a, early = _probe(prober, h.target, owner, approved, obs_list, model)
    if early:
        return early
    obs_b, early = _probe(prober, h.target, other, approved, obs_list, model)
    if early:
        return early
    if obs_a is None or obs_b is None or obs_a.error or obs_b.error:
        err = (obs_a.error if obs_a and obs_a.error else "") or (obs_b.error if obs_b else "")
        return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                      observed="probe failed: %s" % err, observations=obs_list,
                      blocker=BlockerRequest(
                          BlockerKind.ENDPOINT_UNREACHABLE,
                          "a reachable %s" % h.target,
                          "the endpoint did not answer (%s), so the hypothesis is untested, "
                          "not disproved" % err,
                          "confirm the host/session is up, then re-run bbagent research"))
    d = compare(obs_a, obs_b, owner.label, other.label)
    if d.security_relevant:
        return Result(status=HypothesisStatus.SUPPORTED,
                      observed=d.interpretation, observations=obs_list, diff=d.to_dict(),
                      authorization="class B read as two authorized identities")
    obj = ep.object_type if ep else "?"
    if d.outcome_a == d.outcome_b == "absent":
        learned = ("%s returns 404 for both identities: the object id is probably wrong, "
                   "so object-level authorization there is still untested" % h.target)
    elif d.outcome_a == d.outcome_b == "denied":
        learned = ("%s refuses both identities: it needs a privilege neither account has, "
                   "so a higher-privileged account would be needed to test it" % h.target)
    else:
        learned = ("%s enforces object-level authorization for role %s (%s); other endpoints "
                   "on object type %s are less likely to be broken"
                   % (h.target, other.role, d.outcome_b, obj))
    return Result(status=HypothesisStatus.REJECTED,
                  observed=d.interpretation, observations=obs_list, diff=d.to_dict(),
                  learned=learned,
                  authorization="class B read as two authorized identities")


def _role_separation(h, model, prober, approved, obs_list, accounts) -> Result:
    unpriv = next((a for a in accounts if not model.roles.get(a.role, None)
                   or not model.roles[a.role].privileged), None) or ANON
    obs, early = _probe(prober, h.target, unpriv, approved, obs_list, model)
    if early:
        return early
    if obs is None or obs.error:
        return Result(status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                      observed="probe failed: %s" % (obs.error if obs else "no response"),
                      observations=obs_list,
                      blocker=BlockerRequest(BlockerKind.ENDPOINT_UNREACHABLE,
                                             "a reachable %s" % h.target,
                                             "cannot judge role separation without a response",
                                             "check the host, then re-run bbagent research"))
    if obs.ok:
        return Result(status=HypothesisStatus.SUPPORTED,
                      observed="identity %r (role %s) received %d from an endpoint that looks "
                               "privileged" % (unpriv.label, unpriv.role, obs.status),
                      observations=obs_list,
                      authorization="class B read as %s" % unpriv.label)
    return Result(status=HypothesisStatus.REJECTED,
                  observed="identity %r received %s" % (unpriv.label, obs.status),
                  observations=obs_list,
                  learned="privileged path %s refuses role %s; role separation holds there"
                          % (h.target, unpriv.role),
                  authorization="class B read as %s" % unpriv.label)


def _anonymous_reach(h, model, prober, approved, obs_list) -> Result:
    obs, early = _probe(prober, h.target, ANON, approved, obs_list, model)
    if early:
        return early
    if obs is None or obs.error:
        return Result(status=HypothesisStatus.REJECTED,
                      observed="no response: %s" % (obs.error if obs else "none"),
                      observations=obs_list,
                      learned="%s did not answer an anonymous request" % h.target)
    if obs.ok and obs.ids():
        return Result(status=HypothesisStatus.SUPPORTED,
                      observed="anonymous request returned %d with object data (%s)"
                               % (obs.status, ", ".join(obs.ids()[:3])),
                      observations=obs_list, authorization="class B anonymous read")
    if obs.ok:
        return Result(status=HypothesisStatus.REJECTED,
                      observed="anonymous request returned %d but no object data" % obs.status,
                      observations=obs_list,
                      learned="%s is reachable anonymously but exposes no object ids; "
                              "not an authorization gap on its own" % h.target,
                      authorization="class B anonymous read")
    learned = {
        401: "%s requires authentication (401)",
        403: "%s exists but refuses anonymous callers (403)",
        404: "%s does not exist for an anonymous caller (404); it may be absent "
             "entirely or hidden behind auth",
    }.get(obs.status, "%s answered " + str(obs.status) + " to an anonymous request")
    return Result(status=HypothesisStatus.REJECTED,
                  observed="anonymous request returned %s" % obs.status,
                  observations=obs_list,
                  learned=learned % h.target,
                  authorization="class B anonymous read")

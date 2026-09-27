"""Differential analysis.

Comparing two responses as text tells you almost nothing: timestamps, CSRF
tokens and ordering differ on every request. What matters is structural: did the
two identities reach the same OBJECT, and did they get the same PERMISSION
outcome?

This module compares (a) authorization outcomes and (b) object identity, and says
which of the two states is the interesting one. It never decides that something
is a vulnerability -- it produces a comparison that validation can argue with.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

AUTHORIZED = "authorized"
DENIED = "denied"
ABSENT = "absent"
ERROR = "error"


def outcome(obs) -> str:
    """Bucket a response into an authorization outcome."""
    if obs is None or obs.error:
        return ERROR
    if obs.status in (401, 403):
        return DENIED
    if obs.status == 404:
        return ABSENT
    if obs.ok:
        return AUTHORIZED
    return ERROR


@dataclass
class Diff:
    """Structural comparison of one endpoint seen by two states."""
    url: str
    state_a: str                       # account label / description
    state_b: str
    outcome_a: str = ""
    outcome_b: str = ""
    same_object: bool = False          # both responses describe the same object ids
    shared_ids: List[str] = field(default_factory=list)
    only_in_a: List[str] = field(default_factory=list)
    only_in_b: List[str] = field(default_factory=list)
    body_identical: bool = False
    length_delta: int = 0
    interpretation: str = ""
    security_relevant: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compare(obs_a, obs_b, state_a: str = "", state_b: str = "") -> Diff:
    """Compare two observations of the SAME url by two different identities."""
    a_ids = set(obs_a.ids()) if obs_a else set()
    b_ids = set(obs_b.ids()) if obs_b else set()
    d = Diff(
        url=getattr(obs_a, "url", "") or getattr(obs_b, "url", ""),
        state_a=state_a or getattr(obs_a, "account", "a"),
        state_b=state_b or getattr(obs_b, "account", "b"),
        outcome_a=outcome(obs_a),
        outcome_b=outcome(obs_b),
        shared_ids=sorted(a_ids & b_ids),
        only_in_a=sorted(a_ids - b_ids),
        only_in_b=sorted(b_ids - a_ids),
        body_identical=bool(obs_a and obs_b and obs_a.sha256 and obs_a.sha256 == obs_b.sha256),
        length_delta=(getattr(obs_b, "length", 0) - getattr(obs_a, "length", 0)),
    )
    d.same_object = bool(d.shared_ids) or d.body_identical
    d.interpretation, d.security_relevant = _interpret(d)
    return d


def _interpret(d: Diff) -> Tuple[str, bool]:
    """Plain-language reading of the comparison, and whether it is worth a look.

    Deliberately conservative: an equal-and-authorized pair on a resource that
    may be public is NOT called a finding here.
    """
    if ERROR in (d.outcome_a, d.outcome_b):
        return ("at least one state errored; comparison inconclusive", False)
    if d.outcome_a == AUTHORIZED and d.outcome_b == AUTHORIZED and d.same_object:
        return ("both identities reached the same object "
                "(shared ids: %s) -- expected only for shared/public resources"
                % ", ".join(d.shared_ids[:3]), True)
    if d.outcome_a == AUTHORIZED and d.outcome_b in (DENIED, ABSENT):
        return ("owner reached the object, the other identity did not (%s) -- "
                "authorization boundary appears enforced" % d.outcome_b, False)
    if d.outcome_a in (DENIED, ABSENT) and d.outcome_b == AUTHORIZED:
        return ("the identity that should NOT have access got it while the other "
                "did not -- inverted access control, worth validating", True)
    if d.outcome_a == d.outcome_b == DENIED:
        return ("both denied -- endpoint requires something neither state has", False)
    if d.outcome_a == d.outcome_b == ABSENT:
        return ("object not found for either state -- id probably does not exist", False)
    return ("outcomes differ (%s vs %s) without object overlap"
            % (d.outcome_a, d.outcome_b), False)


def compare_permission_sets(matrix_a: Dict[str, str], matrix_b: Dict[str, str]) -> Dict[str, Any]:
    """Compare two roles' observed permission sets across all endpoints.

    Inputs are {endpoint_key: outcome}. Returns the endpoints where the lower
    privileged set reaches what the higher one does -- i.e. missing role
    separation, at the permission-set level rather than per request.
    """
    keys = sorted(set(matrix_a) | set(matrix_b))
    same, only_a, only_b = [], [], []
    for k in keys:
        oa, ob = matrix_a.get(k, ABSENT), matrix_b.get(k, ABSENT)
        if oa == ob == AUTHORIZED:
            same.append(k)
        elif oa == AUTHORIZED:
            only_a.append(k)
        elif ob == AUTHORIZED:
            only_b.append(k)
    return {
        "both_authorized": same,
        "only_a_authorized": only_a,
        "only_b_authorized": only_b,
        "role_separation_intact": not same or bool(only_a or only_b),
    }

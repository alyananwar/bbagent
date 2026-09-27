"""Persistent hypothesis queue.

A hypothesis is the unit of research. It survives restarts, it records why it
was worth testing, what observation would support it, and what actually
happened. A REJECTED hypothesis is not deleted: the thing it taught us is fed
back into the application model, which is how the loop makes progress instead of
looping.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HypothesisStatus(str, Enum):
    UNTESTED = "untested"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"                  # evidence points at it, not confirmed
    REJECTED = "rejected"
    REQUIRES_HUMAN_ACTION = "requires_human_action"
    VALIDATED = "validated"                  # reproduced + security-relevant


OPEN_STATUSES = (HypothesisStatus.UNTESTED, HypothesisStatus.INVESTIGATING)


class Category(str, Enum):
    AUTH = "auth"                            # authentication
    AUTHZ = "authorization"                  # IDOR, role separation, priv-esc
    API = "api"                              # api surface, mass assignment, versions
    BUSINESS_LOGIC = "business_logic"
    BROWSER_WORKFLOW = "browser_workflow"
    INJECTION = "injection"
    CONFIG = "config"
    INFO_DISCLOSURE = "info_disclosure"


@dataclass
class Hypothesis:
    """One testable claim about the target.

    authorization: the action class the test needs (A-E), so the gate can be
    consulted BEFORE anything is attempted rather than after.
    """
    id: str
    category: Category
    target: str
    reasoning: str                           # why the model/plan thinks this
    expected_observation: str                # what we'd see if it were true
    authorization: str = "B"                 # ActionClass value the test needs
    experiment: str = ""                     # which experiment tests it (see investigate.py)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    priority: float = 0.5                    # 0..1, information gain estimate
    status: HypothesisStatus = HypothesisStatus.UNTESTED
    observed: str = ""                       # what actually happened
    learned: str = ""                        # what a rejection taught the model
    parent_id: str = ""                      # hypothesis that spawned this one
    attempts: int = 0
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Hypothesis":
        data = {k: d[k] for k in d if k in cls.__dataclass_fields__}
        data["category"] = Category(data.get("category", "config"))
        data["status"] = HypothesisStatus(data.get("status", "untested"))
        return cls(**data)

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES


# short, non-colliding id prefixes ("auth" vs "authorization" both start "auth")
_PREFIX = {
    Category.AUTH: "authn",
    Category.AUTHZ: "authz",
    Category.API: "api",
    Category.BUSINESS_LOGIC: "logic",
    Category.BROWSER_WORKFLOW: "flow",
    Category.INJECTION: "inj",
    Category.CONFIG: "conf",
    Category.INFO_DISCLOSURE: "info",
}


def make_id(category: Category, target: str, marker: str) -> str:
    """Stable id so the same hypothesis is not re-queued every wave."""
    import hashlib
    key = "%s|%s|%s" % (category.value, target.strip().lower(), marker.strip().lower())
    return "H-%s-%s" % (_PREFIX.get(category, "gen"),
                        hashlib.sha256(key.encode()).hexdigest()[:8])


def replace(h: Hypothesis, **changes: Any) -> Hypothesis:
    """Immutable update: returns a new Hypothesis with changes applied."""
    data = {f: getattr(h, f) for f in h.__dataclass_fields__}
    data.update(changes)
    data["updated_at"] = _now()
    return Hypothesis(**data)


class HypothesisQueue:
    """Priority-ordered view over the stored hypotheses for one engagement.

    Storage is injected (the DB), so this stays testable and the queue is never
    just an in-memory list that dies with the process.
    """

    def __init__(self, store, engagement_id: int):
        self.store = store
        self.eng_id = engagement_id

    def add(self, h: Hypothesis) -> Hypothesis:
        existing = self.store.get_hypothesis(self.eng_id, h.id)
        if existing is not None:
            return existing            # already known; never duplicate work
        self.store.upsert_hypothesis(self.eng_id, h.to_dict())
        return h

    def add_all(self, hs: List[Hypothesis]) -> List[Hypothesis]:
        return [self.add(h) for h in hs]

    def update(self, h: Hypothesis) -> Hypothesis:
        self.store.upsert_hypothesis(self.eng_id, h.to_dict())
        return h

    def all(self) -> List[Hypothesis]:
        return [Hypothesis.from_dict(d) for d in self.store.list_hypotheses(self.eng_id)]

    MAX_ATTEMPTS = 3

    def open(self) -> List[Hypothesis]:
        """Open hypotheses, highest priority first, then oldest first.

        A hypothesis that has been attempted MAX_ATTEMPTS times is not returned:
        retrying it forever would spin the loop instead of advancing it.
        """
        return sorted([h for h in self.all()
                       if h.is_open and h.attempts < self.MAX_ATTEMPTS],
                      key=lambda h: (-h.priority, h.created_at))

    def stuck(self) -> List[Hypothesis]:
        """Open but out of attempts: these need a human, not another retry."""
        return [h for h in self.all() if h.is_open and h.attempts >= self.MAX_ATTEMPTS]

    def next(self) -> Optional[Hypothesis]:
        pending = self.open()
        return pending[0] if pending else None

    def by_status(self, status: HypothesisStatus) -> List[Hypothesis]:
        return [h for h in self.all() if h.status == status]

    def counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in HypothesisStatus}
        for h in self.all():
            out[h.status.value] += 1
        return out

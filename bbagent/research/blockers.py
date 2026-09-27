"""Researcher-action blockers.

When the loop needs something only a human can supply (a second test account, a
session token, permission for a manual-only technique), it raises a blocker with
the reasoning and the exact thing it needs. It does NOT pretend the data exists
and it does NOT end the engagement: the hypothesis parks at
REQUIRES_HUMAN_ACTION, other work continues, and resolving the blocker puts it
back in the queue.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BlockerKind(str, Enum):
    ACCOUNT_NEEDED = "account_needed"
    CREDENTIALS_NEEDED = "credentials_needed"
    ENDPOINT_UNREACHABLE = "endpoint_unreachable"
    MANUAL_ONLY_TECHNIQUE = "manual_only_technique"
    TOOL_MISSING = "tool_missing"
    PROGRAM_CLARIFICATION = "program_clarification"


@dataclass
class Blocker:
    id: str
    kind: BlockerKind
    what_is_needed: str                  # the concrete ask, in one line
    reasoning: str                       # why the research cannot proceed without it
    hypothesis_id: str = ""
    how_to_provide: str = ""             # exact command the human should run
    resolved: bool = False
    resolution: str = ""
    created_at: str = field(default_factory=_now)
    resolved_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Blocker":
        data = {k: d[k] for k in d if k in cls.__dataclass_fields__}
        data["kind"] = BlockerKind(data.get("kind", "program_clarification"))
        return cls(**data)


def make_id(kind: BlockerKind, what: str) -> str:
    import hashlib
    return "B-%s-%s" % (kind.value[:4],
                        hashlib.sha256(("%s|%s" % (kind.value, what)).encode()).hexdigest()[:8])


class BlockerQueue:
    def __init__(self, store, engagement_id: int):
        self.store = store
        self.eng_id = engagement_id

    def raise_blocker(self, kind: BlockerKind, what_is_needed: str, reasoning: str,
                      hypothesis_id: str = "", how_to_provide: str = "") -> Blocker:
        b = Blocker(id=make_id(kind, what_is_needed), kind=kind,
                    what_is_needed=what_is_needed, reasoning=reasoning,
                    hypothesis_id=hypothesis_id, how_to_provide=how_to_provide)
        existing = self.store.get_blocker(self.eng_id, b.id)
        if existing is not None and not existing.get("resolved"):
            return Blocker.from_dict(existing)
        self.store.upsert_blocker(self.eng_id, b.to_dict())
        return b

    def all(self) -> List[Blocker]:
        return [Blocker.from_dict(d) for d in self.store.list_blockers(self.eng_id)]

    def open(self) -> List[Blocker]:
        return [b for b in self.all() if not b.resolved]

    def resolve(self, blocker_id: str, resolution: str) -> Optional[Blocker]:
        d = self.store.get_blocker(self.eng_id, blocker_id)
        if d is None:
            return None
        b = Blocker.from_dict(d)
        b.resolved = True
        b.resolution = resolution
        b.resolved_at = _now()
        self.store.upsert_blocker(self.eng_id, b.to_dict())
        return b

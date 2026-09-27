"""Chronological research log.

Every decision the loop makes is appended: timestamp, agent, hypothesis, action,
authorization verdict, result. This is what makes a clean run defensible -- it
shows what was investigated and rejected, not just what matched.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LogEntry:
    agent: str                       # who decided: planner|modeler|investigator|validator|human
    action: str                      # what was done or decided
    hypothesis_id: str = ""
    authorization: str = ""          # gate verdict + reason, or "n/a (offline)"
    result: str = ""
    state: str = ""                  # research state at the time
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResearchLog:
    def __init__(self, store, engagement_id: int):
        self.store = store
        self.eng_id = engagement_id

    def record(self, agent: str, action: str, hypothesis_id: str = "",
               authorization: str = "", result: str = "", state: str = "") -> LogEntry:
        e = LogEntry(agent=agent, action=action, hypothesis_id=hypothesis_id,
                     authorization=authorization, result=result, state=state)
        self.store.append_research_log(self.eng_id, e.to_dict())
        return e

    def entries(self, limit: Optional[int] = None) -> List[LogEntry]:
        rows = self.store.list_research_log(self.eng_id, limit=limit)
        return [LogEntry(**{k: r[k] for k in r if k in LogEntry.__dataclass_fields__})
                for r in rows]

    def render(self, limit: Optional[int] = None) -> str:
        out = []
        for e in self.entries(limit=limit):
            out.append("%s  %-12s %-22s %s%s%s"
                       % (e.timestamp[11:19], e.agent, e.hypothesis_id or "-", e.action,
                          ("  [auth: %s]" % e.authorization) if e.authorization else "",
                          ("  -> %s" % e.result) if e.result else ""))
        return "\n".join(out)

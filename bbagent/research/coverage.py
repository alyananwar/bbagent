"""Coverage tracking and research budget.

Coverage is measured against what the application model says exists, not against
how many templates a scanner fired. A dimension with no surface discovered is
reported as such rather than as 100%.

The budget is the real stop condition: the loop runs until calls/time run out or
no hypothesis is worth testing. "The scanner finished" is not a stop condition.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .hypothesis import Category, Hypothesis, HypothesisStatus

DIMENSIONS = (
    Category.AUTH,
    Category.AUTHZ,
    Category.API,
    Category.BUSINESS_LOGIC,
    Category.BROWSER_WORKFLOW,
)


@dataclass
class Budget:
    """Research budget. Exhaustion is a legitimate, reportable end state."""
    max_tool_calls: int = 200
    max_seconds: int = 1800
    max_investigations: int = 100
    tool_calls: int = 0
    investigations: int = 0
    started_at: float = field(default_factory=time.time)

    def spend_tool_call(self, n: int = 1) -> None:
        self.tool_calls += n

    def spend_investigation(self, n: int = 1) -> None:
        self.investigations += n

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    def exhausted(self) -> bool:
        return (self.tool_calls >= self.max_tool_calls
                or self.investigations >= self.max_investigations
                or self.elapsed >= self.max_seconds)

    def remaining(self) -> Dict[str, float]:
        return {
            "tool_calls": max(0, self.max_tool_calls - self.tool_calls),
            "investigations": max(0, self.max_investigations - self.investigations),
            "seconds": max(0.0, self.max_seconds - self.elapsed),
        }

    def to_dict(self) -> Dict[str, float]:
        d = {"max_tool_calls": self.max_tool_calls, "max_seconds": self.max_seconds,
             "max_investigations": self.max_investigations,
             "tool_calls": self.tool_calls, "investigations": self.investigations,
             "elapsed": round(self.elapsed, 1)}
        d.update({"remaining_" + k: v for k, v in self.remaining().items()})
        return d


def _bar(fraction: float, width: int = 20) -> str:
    filled = int(round(max(0.0, min(1.0, fraction)) * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def dimension_coverage(hypotheses: List[Hypothesis]) -> Dict[str, Dict[str, float]]:
    """Per dimension: how much of what we thought worth testing has been tested."""
    out: Dict[str, Dict[str, float]] = {}
    for dim in DIMENSIONS:
        hs = [h for h in hypotheses if h.category == dim]
        closed = [h for h in hs if not h.is_open]
        validated = [h for h in hs if h.status == HypothesisStatus.VALIDATED]
        blocked = [h for h in hs if h.status == HypothesisStatus.REQUIRES_HUMAN_ACTION]
        out[dim.value] = {
            "hypotheses": len(hs),
            "tested": len(closed),
            "validated": len(validated),
            "blocked": len(blocked),
            "fraction": (len(closed) / len(hs)) if hs else 0.0,
        }
    return out


def render(hypotheses: List[Hypothesis], budget: Optional[Budget] = None,
           surface: Optional[Dict[str, int]] = None) -> str:
    """Human-readable coverage report. Honest about untouched dimensions."""
    lines = ["RESEARCH COVERAGE"]
    cov = dimension_coverage(hypotheses)
    for dim, c in cov.items():
        if not c["hypotheses"]:
            lines.append("  %-18s %s  no hypotheses generated" % (dim, _bar(0)))
            continue
        lines.append("  %-18s %s %d/%d tested, %d validated%s"
                     % (dim, _bar(c["fraction"]), c["tested"], c["hypotheses"],
                        c["validated"],
                        (", %d blocked on researcher" % c["blocked"]) if c["blocked"] else ""))
    if surface:
        lines.append("\nSURFACE MODELED")
        for k, v in sorted(surface.items()):
            lines.append("  %-18s %d" % (k, v))
    if budget:
        r = budget.remaining()
        lines.append("\nBUDGET")
        lines.append("  tool calls       %d/%d" % (budget.tool_calls, budget.max_tool_calls))
        lines.append("  investigations   %d/%d" % (budget.investigations, budget.max_investigations))
        lines.append("  elapsed          %.0fs of %ds (%.0fs left)"
                     % (budget.elapsed, budget.max_seconds, r["seconds"]))
    return "\n".join(lines)

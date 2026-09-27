"""Engagement research report.

The deliverable is not a list of scanner output. It is: what was modeled, which
hypotheses were tested, which were rejected and what that taught us, what is
validated with evidence, and what is still blocked on a human. A clean run with a
deep report is a result worth reading.
"""
from typing import Any, Dict, List, Optional

from .coverage import render as render_coverage
from .hypothesis import Hypothesis, HypothesisStatus


def render(program: str, state: str, hypotheses: List[Hypothesis],
           findings: List[Dict[str, Any]], blockers: List[Any],
           surface: Dict[str, int], budget=None, log_tail: str = "") -> str:
    out = ["# Research report: %s" % (program or "(unnamed program)"), ""]
    out.append("Final state: **%s**" % state)
    out.append("")
    out.append("```")
    out.append(render_coverage(hypotheses, budget, surface))
    out.append("```")
    out.append("")

    validated = [h for h in hypotheses if h.status == HypothesisStatus.VALIDATED]
    supported = [h for h in hypotheses if h.status == HypothesisStatus.SUPPORTED]
    rejected = [h for h in hypotheses if h.status == HypothesisStatus.REJECTED]
    parked = [h for h in hypotheses if h.status == HypothesisStatus.REQUIRES_HUMAN_ACTION]
    untested = [h for h in hypotheses if h.status == HypothesisStatus.UNTESTED]

    out.append("## Validated findings (%d)" % len(validated))
    if not findings:
        out.append("")
        out.append("None. That is a result, not a failure: the rejected hypotheses below "
                   "record what was tested and why it held up.")
    for f in findings:
        out.append("")
        out.append("### %s" % f.get("title", "(untitled)"))
        out.append("- endpoint: `%s`" % f.get("endpoint", ""))
        out.append("- class: %s" % f.get("vuln_class", ""))
        out.append("- status: %s (confidence %.2f, model estimate)"
                   % (f.get("status", ""), float(f.get("confidence") or 0)))
        if f.get("steps"):
            out.append("- steps:")
            for line in str(f["steps"]).splitlines():
                out.append("  - %s" % line)
        out.append("- observed: %s" % f.get("actual", ""))
        ev = f.get("evidence") or []
        out.append("- evidence: %s" % (", ".join("`%s` (sha256 %s)"
                                                 % (e.get("ref", ""), (e.get("sha256") or "")[:12])
                                                 for e in ev) or "none recorded"))
        out.append("- impact: %s" % (f.get("impact") or "_not assessed; a human writes impact_"))

    if supported:
        out.append("")
        out.append("## Supported, awaiting validation (%d)" % len(supported))
        for h in supported:
            out.append("- `%s` %s — %s" % (h.id, h.target, h.observed))

    out.append("")
    out.append("## Hypotheses tested and rejected (%d)" % len(rejected))
    for h in rejected:
        out.append("")
        out.append("- **%s** (%s, priority %.2f) `%s`" % (h.id, h.category.value, h.priority,
                                                          h.target))
        out.append("  - reasoning: %s" % h.reasoning)
        out.append("  - expected: %s" % h.expected_observation)
        out.append("  - observed: %s" % h.observed)
        if h.learned:
            out.append("  - learned: %s" % h.learned)

    if parked or untested:
        out.append("")
        out.append("## Open work (%d parked on a researcher, %d untested)"
                   % (len(parked), len(untested)))
        for h in parked + untested:
            out.append("- `%s` %s (%s) — %s" % (h.id, h.target, h.status.value,
                                                h.observed or h.reasoning))

    if blockers:
        out.append("")
        out.append("## Researcher action required (%d)" % len(blockers))
        for b in blockers:
            d = b.to_dict() if hasattr(b, "to_dict") else b
            out.append("- **%s**: %s" % (d.get("id"), d.get("what_is_needed")))
            out.append("  - why: %s" % d.get("reasoning"))
            if d.get("how_to_provide"):
                out.append("  - how: `%s`" % d.get("how_to_provide"))

    if log_tail:
        out.append("")
        out.append("## Decision log (most recent)")
        out.append("```")
        out.append(log_tail)
        out.append("```")

    out.append("")
    out.append("_No finding in this report was generated without a recorded, reproduced "
               "observation. Severity and impact are left to a human._")
    return "\n".join(out) + "\n"

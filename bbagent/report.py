"""Submission-ready report generator.

Refuses to emit a report when required, evidence-backed fields are missing rather
than inventing them. Severity/impact are only rendered if the finding actually
carries them. Output is plain markdown.
"""
from typing import List

from .models import Finding

REQUIRED = ("title", "asset", "vuln_class", "steps", "actual")


class IncompleteFinding(Exception):
    pass


def _missing(finding: Finding) -> List[str]:
    return [f for f in REQUIRED if not getattr(finding, f, "").strip()]


def render(finding: Finding, strict: bool = True) -> str:
    missing = _missing(finding)
    if missing and strict:
        raise IncompleteFinding(
            "cannot render report, missing evidence-backed fields: " + ", ".join(missing))

    def section(label: str, value: str) -> str:
        return "## %s\n\n%s\n" % (label, value.strip()) if value and value.strip() else ""

    parts = ["# %s\n" % (finding.title or "(untitled finding)")]
    parts.append(section("Affected Asset", finding.asset))
    parts.append(section("Affected Endpoint", finding.endpoint))
    parts.append(section("Vulnerability Class", finding.vuln_class))
    if finding.severity:
        parts.append(section("Severity", finding.severity))
    parts.append(section("Prerequisites", finding.preconditions))
    parts.append(section("Steps to Reproduce", finding.steps))
    parts.append(section("Expected Result", finding.expected))
    parts.append(section("Actual Result", finding.actual))
    parts.append(section("Proof of Concept", finding.poc))
    if finding.impact:
        parts.append(section("Security Impact", finding.impact))

    if finding.evidence:
        ev = "\n".join("- %s `%s` (sha256 %s)" % (e.get("kind"), e.get("ref"), e.get("sha256", "")[:12])
                       for e in finding.evidence)
        parts.append(section("Evidence", ev))

    if finding.scope_provenance:
        sp = finding.scope_provenance
        parts.append(section("Scope Provenance",
                             "%s — %s" % (sp.get("decision", ""), sp.get("reason", ""))))

    parts.append(section("Confidence (model estimate, not a guarantee)",
                         "%.2f" % finding.confidence))
    if missing and not strict:
        parts.append(section("Incomplete Fields (needs human input)", ", ".join(missing)))

    return "\n".join(p for p in parts if p).strip() + "\n"

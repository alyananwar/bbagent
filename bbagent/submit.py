"""Submitter: check a finalized report against the program's own rules, then
assemble a package a human sends.

Nothing here talks to a bug bounty platform. Submitting is ActionClass.E, it is
irreversible from the program's side, and an unreviewed report costs reputation on
an account that is not the agent's to spend. So this stage produces a package and
a checklist, and `bbagent submitcheck` prints where the human takes over.
"""
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Finding, FindingStatus, ScopePolicy
from . import report as report_mod
from . import scope as scope_mod
from .models import ScopeDecisionKind

# Classes programs commonly rule out. A hit here is a flag for the human, not an
# automatic discard: a rate-limit bypass with real account-takeover impact is a
# different report from "no rate limit on /login".
INELIGIBLE_PATTERNS = (
    (r"\bdos\b|denial[ -]of[ -]service", "DoS / denial of service"),
    (r"rate[ -]limit", "rate limiting or its bypass"),
    (r"missing.{0,20}header", "missing security headers"),
    (r"self[ -]xss", "self-XSS"),
    (r"clickjack", "clickjacking"),
    (r"\bcve-\d{4}-\d+\b", "known CVE"),
    (r"tech[ -]detect|version disclosure|outdated (version|software)", "version disclosure"),
)

BLOCK = "block"
WARN = "warn"


@dataclass
class Issue:
    level: str          # BLOCK or WARN
    code: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"level": self.level, "code": self.code, "detail": self.detail}


@dataclass
class SubmissionCheck:
    finding_id: Optional[int] = None
    issues: List[Issue] = field(default_factory=list)
    report_markdown: str = ""

    @property
    def blockers(self) -> List[Issue]:
        return [i for i in self.issues if i.level == BLOCK]

    @property
    def warnings(self) -> List[Issue]:
        return [i for i in self.issues if i.level == WARN]

    @property
    def ready(self) -> bool:
        return not self.blockers and bool(self.report_markdown)

    def to_dict(self) -> Dict[str, Any]:
        return {"finding_id": self.finding_id, "ready": self.ready,
                "issues": [i.to_dict() for i in self.issues]}


def _ineligible_hits(finding: Finding) -> List[str]:
    haystack = " ".join([finding.title, finding.vuln_class, finding.actual,
                         finding.impact]).lower()
    hits = []
    for pattern, label in INELIGIBLE_PATTERNS:
        if re.search(pattern, haystack):
            hits.append(label)
    return hits


def check(finding: Finding, policy: ScopePolicy,
          finding_id: Optional[int] = None) -> SubmissionCheck:
    """Evaluate one finding for submission readiness. Pure; no I/O, no network."""
    result = SubmissionCheck(finding_id=finding_id)
    issues = result.issues

    # 1. human gate. FINALIZED means a person read the raw finding and certified it.
    if finding.status != FindingStatus.FINALIZED:
        issues.append(Issue(BLOCK, "not_finalized",
                            "status is %s; a human must certify the raw finding first "
                            "(`bbagent approve <id>`)" % finding.status.value))

    # 2. scope, re-checked at submission time and not trusted from earlier
    target = finding.endpoint or finding.asset
    if not target:
        issues.append(Issue(BLOCK, "no_target", "finding names no asset or endpoint"))
    else:
        decision = scope_mod.evaluate(target, policy)
        if decision.decision != ScopeDecisionKind.IN_SCOPE:
            issues.append(Issue(BLOCK, "out_of_scope",
                                "%s is %s at submission time: %s"
                                % (target, decision.decision.value, decision.reason)))

    # 3. evidence. A report with no recorded observation is not a report.
    if not finding.evidence:
        issues.append(Issue(BLOCK, "no_evidence",
                            "no recorded evidence; every claim needs a stored observation"))

    # 4. required fields, delegated to the report renderer so there is one definition
    try:
        result.report_markdown = report_mod.render(finding, strict=True)
    except report_mod.IncompleteFinding as exc:
        issues.append(Issue(BLOCK, "incomplete", str(exc)))

    # 5. program permissions
    perms = policy.permissions
    if finding.poc and not perms.poc_allowed:
        issues.append(Issue(BLOCK, "poc_not_permitted",
                            "the finding carries a proof of concept but the program does "
                            "not permit one; remove it or get that in writing"))

    # 6. likely-ineligible report classes
    for label in _ineligible_hits(finding):
        issues.append(Issue(WARN, "likely_ineligible",
                            "reads as %s, which programs commonly rule ineligible; "
                            "discard it or show fresh impact" % label))

    # 7. things only a human can supply
    if not finding.impact.strip():
        issues.append(Issue(WARN, "no_impact",
                            "security impact is blank; a human writes impact, the agent does not"))
    if not finding.severity.strip():
        issues.append(Issue(WARN, "no_severity", "severity unset; set it yourself if the program wants one"))

    return result


def package(finding: Finding, policy: ScopePolicy, program: str = "",
            finding_id: Optional[int] = None) -> str:
    """Markdown package: the checklist, then the report body to paste."""
    result = check(finding, policy, finding_id=finding_id)
    out = ["# Submission package: %s" % (finding.title or "(untitled finding)"), ""]
    out.append("Program: %s" % (program or "(unnamed)"))
    out.append("Finding: %s" % ("#%d" % finding_id if finding_id else "(unsaved)"))
    out.append("Status: **%s**" % ("ready for a human to send" if result.ready
                                   else "NOT ready"))
    out.append("")

    if result.blockers:
        out.append("## Blocking (%d)" % len(result.blockers))
        for i in result.blockers:
            out.append("- **%s**: %s" % (i.code, i.detail))
        out.append("")
    if result.warnings:
        out.append("## Read before sending (%d)" % len(result.warnings))
        for i in result.warnings:
            out.append("- %s: %s" % (i.code, i.detail))
        out.append("")

    out.append("## Program rules as parsed")
    perms = policy.permissions
    out.append("- active testing: %s" % ("allowed" if perms.active_testing_allowed else "not stated"))
    out.append("- automated scanning: %s" % ("allowed" if perms.automated_scanning_allowed else "not allowed"))
    out.append("- proof of concept: %s" % ("allowed" if perms.poc_allowed else "not permitted"))
    if perms.rate_limit_rps:
        out.append("- rate limit observed: %g req/sec" % perms.rate_limit_rps)
    if perms.prohibited_techniques:
        out.append("- prohibited: %s" % ", ".join(sorted(set(perms.prohibited_techniques))))
    if policy.source_url:
        out.append("- brief source: %s" % policy.source_url)
    out.append("")

    if result.report_markdown:
        out.append("## Report body")
        out.append("")
        out.append(result.report_markdown.strip())
        out.append("")

    out.append("## Sending it")
    out.append("")
    out.append("bbagent does not submit. Paste the report body into the program's own "
               "submission form yourself, then record it:")
    out.append("")
    out.append("```bash")
    out.append("# after you have submitted it by hand")
    out.append("bbagent submitted %s" % (str(finding_id) if finding_id else "<finding id>"))
    out.append("```")
    return "\n".join(out) + "\n"


def write_package(path: str, text: str) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path

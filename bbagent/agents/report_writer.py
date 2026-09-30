"""Optional LLM polish over a deterministic report.

report.render() is authoritative and always produces the report. This adds an
optional prose cleanup that must NOT introduce new facts (no new impact,
severity, endpoints, or results). If the model adds anything not present in the
deterministic report, callers should prefer the deterministic version.
"""
from ..models import Finding, FindingStatus
from .. import report
from ..llm.base import Provider

_SYSTEM = (
    "You are editing a security finding report for clarity only. You must NOT add, "
    "remove, or change any technical fact: keep every asset, endpoint, severity, "
    "step, and result exactly. Do not invent impact or CVSS. Improve wording and "
    "flow only. Return the edited markdown, nothing else."
)


def polish(finding: Finding, provider: Provider) -> str:
    base = report.render(finding, strict=True)   # authoritative; raises if incomplete
    edited = provider.complete(_SYSTEM, [{"role": "user", "content": base}],
                               tier="strong", max_tokens=4000)
    return edited.strip() or base


# --- Storyteller -----------------------------------------------------------

_STORYTELLER = (
    "You are a pragmatic security engineer writing up a bug you found. You hate "
    "fluff and you can tell when something was written by a language model.\n"
    "\n"
    "Rules you do not break:\n"
    "- Every technical fact in the draft stays exactly as it is: assets, endpoints, "
    "HTTP methods, status codes, ids, steps, observed results, evidence hashes.\n"
    "- You add NO new facts. No invented impact, no severity, no CVSS, no guessed "
    "root cause, no 'an attacker could then...' chain that the evidence does not show. "
    "If impact is blank in the draft it stays blank; a human writes impact.\n"
    "- No AI tells: no 'delve', 'leverage', 'robust', 'it is worth noting', no "
    "em-dashes, no three-item lists for their own sake, no closing paragraph that "
    "restates the report.\n"
    "- Write plainly. Short sentences. Say what you did, what you expected, what "
    "happened instead. A triager should be able to reproduce it without asking you "
    "a question.\n"
    "\n"
    "Return the edited markdown and nothing else."
)


class NotCertified(Exception):
    """Raised when narration is attempted before a human certified the finding."""


def narrate(finding: Finding, provider: Provider, require_certified: bool = True) -> str:
    """Storyteller stage: rewrite the deterministic report in a human voice.

    Refuses by default until the finding is FINALIZED, which is the human
    checkpoint: a person read the raw finding and certified it before any prose got
    written about it. That ordering is the whole point, so it is on by default.
    """
    if require_certified and finding.status != FindingStatus.FINALIZED:
        raise NotCertified(
            "finding is %s, not finalized. A human certifies the raw finding before "
            "the report gets written: run `bbagent approve <id>` first."
            % finding.status.value)
    base = report.render(finding, strict=True)
    edited = provider.complete(_STORYTELLER, [{"role": "user", "content": base}],
                               tier="strong", max_tokens=4000)
    return edited.strip() or base

"""Optional LLM polish over a deterministic report.

report.render() is authoritative and always produces the report. This adds an
optional prose cleanup that must NOT introduce new facts (no new impact,
severity, endpoints, or results). If the model adds anything not present in the
deterministic report, callers should prefer the deterministic version.
"""
from ..models import Finding
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

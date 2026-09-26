"""Finding validation pipeline.

A potential finding does not become a report because a scanner or an LLM said so.
It has to survive: scope check -> dedup -> independent reproduction -> confidence
scoring. Anything that can't be reproduced stays a draft or is rejected. Live
reproduction is injected as a callable so this module has no network of its own
and stays fully testable.
"""
from typing import Callable, List, Optional, Tuple

from .models import Finding, FindingStatus, ScopePolicy, ScopeDecisionKind
from . import scope, dedup

# reproduce_fn(finding) -> (reproduced: bool, evidence_note: str)
ReproduceFn = Callable[[Finding], Tuple[bool, str]]

_SEVERITY_WEIGHT = {"critical": 0.4, "high": 0.3, "medium": 0.2, "low": 0.1, "info": 0.05, "": 0.1}
_MAX_UNREPRODUCED_CONFIDENCE = 0.5


def _base_confidence(finding: Finding) -> float:
    return _SEVERITY_WEIGHT.get((finding.severity or "").lower(), 0.1)


def validate(finding: Finding,
             policy: ScopePolicy,
             existing_fingerprints: Optional[List[str]] = None,
             reproduce_fn: Optional[ReproduceFn] = None,
             rejected_fingerprints: Optional[List[str]] = None) -> Finding:
    """Return a NEW Finding with updated status/confidence/fingerprint.

    Immutable style: does not mutate the input.
    """
    existing_fingerprints = existing_fingerprints or []
    rejected_fingerprints = rejected_fingerprints or []

    result = Finding(**{f: getattr(finding, f) for f in finding.__dataclass_fields__})
    result.fingerprint = finding.fingerprint or dedup.fingerprint(finding)

    # 1. scope: a finding on an out-of-scope / unknown asset is not reportable
    sd = scope.evaluate(finding.endpoint or finding.asset, policy)
    result.scope_provenance = sd.to_dict()
    if sd.decision != ScopeDecisionKind.IN_SCOPE:
        result.status = FindingStatus.REJECTED
        result.confidence = 0.0
        return result

    # 2. dedup against current + previously-rejected findings
    if result.fingerprint in set(existing_fingerprints):
        result.status = FindingStatus.DUPLICATE
        return result
    if result.fingerprint in set(rejected_fingerprints):
        result.status = FindingStatus.REJECTED
        result.confidence = 0.0
        return result

    # 3. independent reproduction
    conf = _base_confidence(finding)
    if reproduce_fn is None:
        result.confidence = min(conf, _MAX_UNREPRODUCED_CONFIDENCE)
        result.status = FindingStatus.DRAFT       # needs a human / a reproduce step
        return result

    ok, note = reproduce_fn(finding)
    if not ok:
        result.status = FindingStatus.REJECTED
        result.confidence = min(conf, 0.2)
        result.actual = (result.actual + "\n[repro failed] " + note).strip()
        return result

    result.confidence = min(1.0, conf + 0.5)
    result.status = FindingStatus.VALIDATED
    result.actual = (result.actual + "\n[reproduced] " + note).strip()
    return result

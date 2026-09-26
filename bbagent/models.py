"""Core data models for an engagement.

Plain dataclasses + enums. No behavior beyond serialization. The scope and
policy logic that acts on these lives in scope.py / policy.py so that the
security-critical decisions are testable in isolation.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- enums -----------------------------------------------------------------

class RuleKind(str, Enum):
    DOMAIN = "domain"                 # exact host: api.example.com
    WILDCARD_DOMAIN = "wildcard_domain"  # *.example.com (subdomains)
    URL = "url"                       # scheme+host+path prefix
    IP = "ip"                         # single address
    CIDR = "cidr"                     # network range (only if authorized)
    PORT = "port"                     # host:port (only if authorized)
    REPO = "repo"                     # source repository
    OTHER = "other"


class ScopeDecisionKind(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


class ActionClass(str, Enum):
    A_PASSIVE = "A"            # reading docs, offline reasoning
    B_LOW_ACTIVE = "B"        # normal HTTP, crawling, tech id
    C_SECURITY_TEST = "C"     # auth/injection/fuzz/controlled PoC
    D_IMPACTFUL = "D"         # state change, high volume, real user data
    E_EXTERNAL = "E"          # submit report, message staff, publish


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class FindingStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    FINALIZED = "finalized"       # immutable
    SUBMITTED = "submitted"       # human submitted externally


# --- scope -----------------------------------------------------------------

@dataclass
class ScopeRule:
    kind: RuleKind
    value: str
    source: str = "manual"           # provenance: where this rule came from
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class ProgramPermissions:
    """Program-declared permissions. Everything defaults to the SAFE value
    (not permitted) so an unparsed brief can never accidentally authorize."""
    automated_scanning_allowed: bool = False
    active_testing_allowed: bool = False
    poc_allowed: bool = False
    production_testing_allowed: bool = False
    prohibited_techniques: List[str] = field(default_factory=list)
    rate_limit_rps: Optional[float] = None
    required_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScopePolicy:
    in_scope: List[ScopeRule] = field(default_factory=list)
    out_of_scope: List[ScopeRule] = field(default_factory=list)
    permissions: ProgramPermissions = field(default_factory=ProgramPermissions)
    raw_source: str = ""             # original brief text, kept for traceability
    source_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "in_scope": [r.to_dict() for r in self.in_scope],
            "out_of_scope": [r.to_dict() for r in self.out_of_scope],
            "permissions": self.permissions.to_dict(),
            "raw_source": self.raw_source,
            "source_url": self.source_url,
        }


# --- engagement ------------------------------------------------------------

@dataclass
class Engagement:
    platform: str = ""
    program: str = ""
    program_url: str = ""
    policy: ScopePolicy = field(default_factory=ScopePolicy)
    authentication: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    status: str = "awaiting_scope_confirmation"
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "program": self.program,
            "program_url": self.program_url,
            "policy": self.policy.to_dict(),
            "authentication": self.authentication,
            "notes": self.notes,
            "status": self.status,
            "created_at": self.created_at,
        }


# --- decisions / provenance ------------------------------------------------

@dataclass
class ScopeDecision:
    target: str
    decision: ScopeDecisionKind
    matched_rule: Optional[Dict[str, Any]] = None
    reason: str = ""
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


@dataclass
class ToolRun:
    tool: str
    version: str
    args: List[str]
    target: str
    scope_decision: Dict[str, Any]
    verdict: str
    exit_code: Optional[int] = None
    stdout_ref: str = ""
    stderr_ref: str = ""
    started_at: str = field(default_factory=_now)
    finished_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --- findings / evidence ---------------------------------------------------

@dataclass
class Evidence:
    kind: str                        # http_request, http_response, screenshot, log, tool_output
    ref: str                         # path in the evidence store
    sha256: str
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    title: str
    asset: str
    endpoint: str = ""
    vuln_class: str = ""
    preconditions: str = ""
    steps: str = ""
    expected: str = ""
    actual: str = ""
    impact: str = ""
    poc: str = ""
    confidence: float = 0.0          # 0..1, model estimate — labeled as such
    severity: str = ""               # only when justified; never invented
    scope_provenance: Optional[Dict[str, Any]] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    status: FindingStatus = FindingStatus.DRAFT
    fingerprint: str = ""
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

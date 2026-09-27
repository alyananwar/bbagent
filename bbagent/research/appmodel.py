"""Structured application model.

A URL list says nothing about authorization. This models what an endpoint
actually is: it OPERATES ON an object, it REQUIRES a role, and it may CHANGE
state. With roles and researcher-controlled accounts alongside it, the agent can
reason over an authorization matrix ("role X should not reach object type Y")
instead of guessing from paths.

Accounts are researcher-controlled test identities. Their auth material is a
reference to a secret the human supplied, never invented: a missing account is a
blocker, not an assumption.
"""
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_ID_SEG = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,})$", re.I)
# "Header=env:VAR" and nothing else. A raw token pasted here would be written to
# the app_models table verbatim, which is exactly what must never happen.
_TOKEN_REF = re.compile(r"^[^=\s][^=]*=env:[A-Za-z_][A-Za-z0-9_]*$")


class UnsafeTokenRef(ValueError):
    """Raised when auth material is passed where only a reference belongs."""


def check_token_ref(token_ref: str) -> None:
    if token_ref and not _TOKEN_REF.match(token_ref.strip()):
        raise UnsafeTokenRef(
            "token_ref must be 'Header=env:VAR' (a reference to an environment "
            "variable), not the secret itself. Got %r. Nothing was saved: export the "
            "value in your shell and pass the variable name instead."
            % (token_ref[:16] + "..." if len(token_ref) > 16 else token_ref))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Role:
    name: str                               # anonymous|user|admin|support|...
    description: str = ""
    privileged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Account:
    """A researcher-controlled test identity.

    auth_state: "none" | "credentials_provided" | "authenticated"
    token_ref:  where the secret lives (env var name or evidence ref). The secret
                itself is never stored in the model or the DB.
    """
    label: str                              # "A", "B", "admin"
    role: str = "user"
    auth_state: str = "none"
    token_ref: str = ""
    identity: str = ""                      # user id/email the program gave us
    owns: List[str] = field(default_factory=list)   # object ids it legitimately owns
    notes: str = ""

    def __post_init__(self) -> None:
        check_token_ref(self.token_ref)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def usable(self) -> bool:
        return self.auth_state in ("credentials_provided", "authenticated") and bool(self.token_ref)


@dataclass
class Resource:
    """An object type the application exposes (order, invoice, user, ...)."""
    name: str
    id_pattern: str = ""                    # e.g. /orders/{id}
    owner_scoped: bool = True               # should be visible only to its owner
    observed_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointModel:
    """Endpoint operates on object, requires role, changes state."""
    url: str
    method: str = "GET"
    object_type: str = ""                   # Resource.name it operates on
    object_id: str = ""                     # concrete id seen in the URL, if any
    requires_role: str = "unknown"
    changes_state: bool = False
    params: List[str] = field(default_factory=list)
    observed_status: Optional[int] = None
    # conclusions learned from investigations, so a rejection makes the model
    # smarter instead of only closing a ticket
    notes: List[str] = field(default_factory=list)
    provenance: str = ""
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def key(self) -> str:
        return "%s %s" % (self.method.upper(), self.url)


_STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")
_PRIV_HINTS = ("admin", "internal", "manage", "staff", "moderat", "superuser")


def classify_path(url: str) -> Tuple[str, str, List[str]]:
    """Return (object_type, object_id, params) from a URL, structurally.

    /api/v2/orders/1042/items?expand=1 -> ("orders", "1042", ["expand"])
    """
    from urllib.parse import urlparse, parse_qs
    p = urlparse(url)
    segs = [s for s in (p.path or "").split("/") if s]
    params = sorted(parse_qs(p.query or "").keys())
    obj, oid = "", ""
    for i, seg in enumerate(segs):
        if _ID_SEG.match(seg):
            oid = seg
            if i > 0:
                obj = segs[i - 1].lower()
            break
    if not obj:
        skip = {"api", "v1", "v2", "v3", "graphql", "rest"}
        named = [s.lower() for s in segs if s.lower() not in skip and "." not in s]
        obj = named[-1] if named else ""
    return obj, oid, params


def infer_endpoint(url: str, method: str = "GET", provenance: str = "",
                   status: Optional[int] = None) -> EndpointModel:
    obj, oid, params = classify_path(url)
    role = "unknown"
    low = url.lower()
    if any(h in low for h in _PRIV_HINTS):
        role = "privileged"
    return EndpointModel(url=url, method=method.upper(), object_type=obj, object_id=oid,
                         requires_role=role, changes_state=method.upper() in _STATE_CHANGING,
                         params=params, observed_status=status, provenance=provenance)


class AppModel:
    """Roles + accounts + resources + endpoints, and the matrix over them."""

    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.accounts: Dict[str, Account] = {}
        self.resources: Dict[str, Resource] = {}
        self.endpoints: Dict[str, EndpointModel] = {}
        # (role, endpoint_key) -> "allowed" | "denied" | "unknown"
        self.matrix: Dict[str, str] = {}

    # --- mutation (adds are idempotent by key) ---
    def add_role(self, role: Role) -> Role:
        return self.roles.setdefault(role.name, role)

    def add_account(self, acct: Account) -> Account:
        self.accounts[acct.label] = acct
        self.add_role(Role(acct.role, privileged=acct.role in ("admin", "staff")))
        return acct

    def add_resource(self, res: Resource) -> Resource:
        existing = self.resources.get(res.name)
        if existing is None:
            self.resources[res.name] = res
            return res
        for oid in res.observed_ids:
            if oid not in existing.observed_ids:
                existing.observed_ids.append(oid)
        return existing

    def add_endpoint(self, ep: EndpointModel) -> EndpointModel:
        existing = self.endpoints.get(ep.key)
        if existing is not None:
            if ep.observed_status is not None:
                existing.observed_status = ep.observed_status
            for p in ep.params:
                if p not in existing.params:
                    existing.params.append(p)
            return existing
        self.endpoints[ep.key] = ep
        if ep.object_type:
            self.add_resource(Resource(ep.object_type,
                                       id_pattern="%s/{id}" % ep.object_type,
                                       observed_ids=[ep.object_id] if ep.object_id else []))
        return ep

    def observe(self, role: str, endpoint_key: str, outcome: str) -> None:
        """Record what a role actually got: allowed | denied."""
        self.matrix["%s|%s" % (role, endpoint_key)] = outcome

    def learn(self, endpoint_key: str, note: str) -> None:
        """Attach a conclusion to an endpoint. Idempotent."""
        ep = self.endpoints.get(endpoint_key)
        if ep is not None and note and note not in ep.notes:
            ep.notes.append(note)

    def access(self, role: str, endpoint_key: str) -> str:
        return self.matrix.get("%s|%s" % (role, endpoint_key), "unknown")

    # --- reasoning ---
    def object_scoped_endpoints(self) -> List[EndpointModel]:
        """Endpoints addressing a concrete object id: the IDOR/authz surface."""
        return [e for e in self.endpoints.values() if e.object_id]

    def privileged_endpoints(self) -> List[EndpointModel]:
        return [e for e in self.endpoints.values() if e.requires_role == "privileged"]

    def state_changing_endpoints(self) -> List[EndpointModel]:
        return [e for e in self.endpoints.values() if e.changes_state]

    def unknown_authorization(self) -> List[EndpointModel]:
        """Endpoints we have never observed any role's access to: the gaps."""
        out = []
        for ep in self.endpoints.values():
            if not any(k.endswith("|" + ep.key) for k in self.matrix):
                out.append(ep)
        return out

    def usable_accounts(self) -> List[Account]:
        return [a for a in self.accounts.values() if a.usable]

    def roles_with_accounts(self) -> List[str]:
        return sorted({a.role for a in self.usable_accounts()})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "roles": {k: v.to_dict() for k, v in self.roles.items()},
            "accounts": {k: v.to_dict() for k, v in self.accounts.items()},
            "resources": {k: v.to_dict() for k, v in self.resources.items()},
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
            "matrix": dict(self.matrix),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppModel":
        m = cls()

        def _mk(klass, d):
            return klass(**{k: d[k] for k in d if k in klass.__dataclass_fields__})

        for k, v in (data.get("roles") or {}).items():
            m.roles[k] = _mk(Role, v)
        for k, v in (data.get("accounts") or {}).items():
            m.accounts[k] = _mk(Account, v)
        for k, v in (data.get("resources") or {}).items():
            m.resources[k] = _mk(Resource, v)
        for k, v in (data.get("endpoints") or {}).items():
            m.endpoints[k] = _mk(EndpointModel, v)
        m.matrix = dict(data.get("matrix") or {})
        return m


def from_graph(graph, model: Optional[AppModel] = None) -> AppModel:
    """Fold the recon surface graph into a structured model.

    This is the step that was missing: endpoints stopped being URLs and became
    objects with owners and required roles.
    """
    m = model or AppModel()
    m.add_role(Role("anonymous", "no credentials"))
    for node in graph.by_type("endpoint") + graph.by_type("url"):
        status = (node.attrs or {}).get("status")
        m.add_endpoint(infer_endpoint(node.value, "GET", node.provenance, status))
    return m

"""Targeted HTTP probe for investigations.

Recon tools answer broad questions loudly. An investigation asks one narrow
question quietly: "does account A see account B's object?". That needs a single
request, as a chosen identity, through the same scope + policy gate as any tool,
with the response recorded as evidence.

stdlib urllib only. Secrets are read from the environment at request time and
never stored: an account's token_ref names the variable, e.g.
"Authorization=env:BB_TOKEN_A" or "Cookie=env:BB_SESSION_B".
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..models import ActionClass, ScopePolicy, Verdict
from .. import toolrun

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
_REDIRECT_CODES = (301, 302, 303, 307, 308)
_SNIPPET = 2000
_MAX_BODY = 512 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect.

    urllib follows them by default, which would take a probe to whatever host the
    target names -- possibly out of scope, with our auth header attached. A 3xx is
    recorded as an observation; if the destination is worth probing it goes through
    the gate as its own request.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class NotAuthorized(Exception):
    """The gate refused this probe. Carries the reason for the research log."""

    def __init__(self, verdict: str, reason: str):
        super().__init__("%s: %s" % (verdict, reason))
        self.verdict = verdict
        self.reason = reason


@dataclass
class Observation:
    """What one request actually returned. The unit of evidence."""
    url: str
    method: str
    account: str = "anonymous"
    status: Optional[int] = None
    length: int = 0
    sha256: str = ""
    content_type: str = ""
    snippet: str = ""
    evidence_ref: str = ""
    error: str = ""
    redirect_to: str = ""            # recorded, never followed (see _NoRedirect)
    elapsed_ms: int = 0
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def ids(self) -> List[str]:
        """Object ids visible in the body, for structural (not textual) compare."""
        return sorted(_collect_ids(self.snippet))


def _collect_ids(body: str) -> List[str]:
    out: List[str] = []
    try:
        data = json.loads(body)
    except ValueError:
        return out

    def walk(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("id", "uuid", "user_id", "userid", "owner", "owner_id",
                                 "account_id", "email") and not isinstance(v, (dict, list)):
                    out.append("%s.%s=%s" % (path, k, v))
                walk(v, "%s.%s" % (path, k) if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))

    walk(data)
    return out


def account_headers(account, required: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, str], str]:
    """Build request headers for an account. Returns (headers, missing_reason).

    A missing secret is reported, never faked: the caller turns that into a
    RESEARCHER_ACTION blocker.
    """
    headers = dict(required or {})
    if account is None or account.label == "anonymous" or not account.token_ref:
        return headers, ""
    ref = account.token_ref
    if "=env:" not in ref:
        return headers, "token_ref %r is not in the form Header=env:VAR" % ref
    header_name, var = ref.split("=env:", 1)
    value = os.environ.get(var.strip(), "")
    if not value:
        return headers, "environment variable %s is not set" % var.strip()
    headers[header_name.strip()] = value
    return headers, ""


class Prober:
    """Gated single-request prober.

    Every call re-runs the scope + policy gate: an investigation never gets a
    pass because recon was authorized earlier.
    """

    def __init__(self, policy: ScopePolicy, store=None, timeout: int = 20,
                 rps: Optional[float] = None):
        self.policy = policy
        self.store = store
        self.timeout = timeout
        self.rps = rps or policy.permissions.rate_limit_rps or 5.0
        self._last = 0.0

    def _throttle(self) -> None:
        gap = 1.0 / float(self.rps) if self.rps else 0.0
        wait = gap - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def gate(self, url: str, method: str) -> Tuple[Verdict, Any, str, ActionClass]:
        cls = ActionClass.B_LOW_ACTIVE if method.upper() in SAFE_METHODS else ActionClass.D_IMPACTFUL
        verdict, sd, reason = toolrun.gate(url, cls, self.policy)
        return verdict, sd, reason, cls

    def request(self, url: str, method: str = "GET", account=None,
                approved: bool = False, body: Optional[bytes] = None) -> Observation:
        """One gated request. Raises NotAuthorized rather than probing anyway."""
        # urllib's default opener also speaks ftp://, file:// and data:. This
        # prober is an HTTP prober; anything else is refused before the gate.
        scheme = (urllib.parse.urlparse(url).scheme or "").lower()
        if scheme not in ("http", "https"):
            raise NotAuthorized("deny", "only http(s) targets may be probed, got %r" % scheme)
        verdict, sd, reason, cls = self.gate(url, method)
        if verdict == Verdict.DENY:
            raise NotAuthorized("deny", reason)
        if verdict == Verdict.REQUIRE_APPROVAL and not approved:
            raise NotAuthorized("require_approval", reason)

        headers, missing = account_headers(account, self.policy.permissions.required_headers)
        label = getattr(account, "label", "anonymous")
        if missing:
            return Observation(url=url, method=method.upper(), account=label,
                               error="missing auth material: %s" % missing)

        req = urllib.request.Request(url, method=method.upper(), data=body)
        for k, v in headers.items():
            req.add_header(k, v)

        self._throttle()
        started = time.time()
        obs = Observation(url=url, method=method.upper(), account=label)
        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_BODY)
                obs.status = resp.status
                obs.content_type = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:            # 3xx/4xx/5xx are observations
            raw = e.read(_MAX_BODY) if hasattr(e, "read") else b""
            obs.status = e.code
            obs.content_type = e.headers.get("Content-Type", "") if e.headers else ""
            if e.code in _REDIRECT_CODES and e.headers:
                obs.redirect_to = e.headers.get("Location", "")
        except Exception as e:                          # noqa: BLE001 - network/DNS/TLS
            obs.error = "%s: %s" % (type(e).__name__, e)
            obs.elapsed_ms = int((time.time() - started) * 1000)
            return obs

        text = raw.decode("utf-8", "replace")
        obs.length = len(raw)
        obs.sha256 = hashlib.sha256(raw).hexdigest()
        obs.snippet = text[:_SNIPPET]
        obs.elapsed_ms = int((time.time() - started) * 1000)
        if self.store is not None:
            ev = self.store.add("http_response", raw)
            obs.evidence_ref = ev.ref
        return obs

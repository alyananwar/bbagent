"""Browser to API correlation.

A crawler sees a single-page app as one HTML shell. The researcher's own browser
sees what the app actually does: which backend requests one UI action fires, what
objects those requests address, and which credential they carry. This module turns
a captured network log into application-model endpoints tagged with the workflow
that produced them.

Two inputs are supported, both offline:
  - a HAR file exported from DevTools
  - the JSON shape the browser automation tool returns for network requests

Secrets never survive the import. Header VALUES for anything authentication-bearing
are dropped at parse time and replaced with a classification (cookie / bearer /
api_token), so the model records THAT a request was authenticated and how, never
the credential itself.
"""
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from .appmodel import AppModel, EndpointModel, infer_endpoint

# header names whose values must never be written anywhere
_SECRET_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
                   "proxy-authorization", "x-csrf-token", "x-xsrf-token")
_REDACTED = "[redacted]"

# request types that are page furniture, not API surface
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
               ".woff2", ".ttf", ".ico", ".map", ".webp", ".avif")


@dataclass
class ObservedRequest:
    """One backend request the browser made, with its credential stripped."""
    url: str
    method: str = "GET"
    status: Optional[int] = None
    workflow: str = ""                  # the UI action the researcher labelled
    auth_kind: str = "none"             # none | cookie | bearer | api_token
    auth_header: str = ""               # the header NAME only, never its value
    request_body_keys: List[str] = field(default_factory=list)
    response_type: str = ""
    order: int = 0                      # position within the workflow

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classify_auth(headers: Dict[str, str]) -> Tuple[str, str]:
    """Return (auth_kind, header_name). Values are never read past this point."""
    lowered = {k.lower(): (v or "") for k, v in headers.items()}
    if "authorization" in lowered:
        value = lowered["authorization"].strip()
        kind = "bearer" if value.lower().startswith("bearer ") else "api_token"
        return kind, "Authorization"
    if "cookie" in lowered:
        return "cookie", "Cookie"
    for name in ("x-api-key", "x-auth-token"):
        if name in lowered:
            return "api_token", name
    return "none", ""


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k: (_REDACTED if k.lower() in _SECRET_HEADERS else v)
            for k, v in headers.items()}


def _is_api_call(url: str, response_type: str = "") -> bool:
    path = (urlparse(url).path or "").lower()
    if path.endswith(_STATIC_EXT):
        return False
    if "/api/" in path or "/graphql" in path or "/internal/" in path or "/private/" in path:
        return True
    return "json" in (response_type or "").lower()


def _body_keys(body: Any) -> List[str]:
    """Top-level keys of a JSON request body. Values are ignored on purpose: they
    may contain the researcher's data and are not needed to model the endpoint."""
    if not body:
        return []
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return sorted(parse_qs(body).keys()) if "=" in body else []
    if isinstance(body, dict):
        return sorted(str(k) for k in body.keys())
    return []


def _header_map(entries: Iterable[Any]) -> Dict[str, str]:
    """HAR stores headers as [{name, value}]; tools often use a plain dict."""
    if isinstance(entries, dict):
        return {str(k): str(v) for k, v in entries.items()}
    out: Dict[str, str] = {}
    for h in entries or []:
        if isinstance(h, dict) and "name" in h:
            out[str(h["name"])] = str(h.get("value", ""))
    return out


def from_har(raw: str, workflow: str = "") -> List[ObservedRequest]:
    """Parse a DevTools HAR export into observed API requests."""
    data = json.loads(raw)
    entries = (data.get("log") or {}).get("entries") or []
    out: List[ObservedRequest] = []
    for i, e in enumerate(entries):
        req = e.get("request") or {}
        resp = e.get("response") or {}
        url = req.get("url", "")
        ctype = ((resp.get("content") or {}).get("mimeType")
                 or _header_map(resp.get("headers")).get("Content-Type", ""))
        if not url or not _is_api_call(url, ctype):
            continue
        headers = _header_map(req.get("headers"))
        kind, name = classify_auth(headers)
        out.append(ObservedRequest(
            url=url, method=(req.get("method") or "GET").upper(),
            status=resp.get("status"), workflow=workflow,
            auth_kind=kind, auth_header=name,
            request_body_keys=_body_keys((req.get("postData") or {}).get("text")),
            response_type=ctype, order=i))
    return out


def from_records(records: Iterable[Dict[str, Any]], workflow: str = "") -> List[ObservedRequest]:
    """Parse the flat {url, method, status, requestHeaders, requestBody} shape that
    browser automation tools return."""
    out: List[ObservedRequest] = []
    for i, r in enumerate(records or []):
        url = r.get("url") or ""
        ctype = r.get("responseType") or r.get("contentType") or ""
        if not url or not _is_api_call(url, ctype):
            continue
        headers = _header_map(r.get("requestHeaders") or r.get("headers") or {})
        kind, name = classify_auth(headers)
        out.append(ObservedRequest(
            url=url, method=str(r.get("method") or "GET").upper(),
            status=r.get("status") or r.get("statusCode"), workflow=workflow,
            auth_kind=kind, auth_header=name,
            request_body_keys=_body_keys(r.get("requestBody") or r.get("postData")),
            response_type=ctype, order=i))
    return out


def fold(model: AppModel, requests: List[ObservedRequest]) -> List[EndpointModel]:
    """Fold observed requests into the application model.

    This is where a UI action becomes structure: the endpoint gets its method,
    object type and id, its parameters (including request body keys, which a
    crawler can never see), and a note naming the workflow that reached it.
    """
    added: List[EndpointModel] = []
    for r in requests:
        ep = infer_endpoint(r.url, r.method, provenance="browser:%s" % (r.workflow or "session"),
                            status=r.status)
        stored = model.add_endpoint(ep)
        for key in r.request_body_keys:
            if key not in stored.params:
                stored.params.append(key)
        if r.workflow:
            model.learn(stored.key, "reached by UI workflow %r (step %d), auth: %s"
                        % (r.workflow, r.order, r.auth_kind))
        # an authenticated 2xx tells us the caller's role could reach it
        if r.status and 200 <= r.status < 300:
            model.observe("browser_session" if r.auth_kind != "none" else "anonymous",
                          stored.key, "authorized")
        elif r.status in (401, 403):
            model.observe("browser_session" if r.auth_kind != "none" else "anonymous",
                          stored.key, "denied")
        added.append(stored)
    return added


def workflow_summary(requests: List[ObservedRequest]) -> Dict[str, Any]:
    """What the capture actually contained, for the research log."""
    workflows: Dict[str, int] = {}
    methods: Dict[str, int] = {}
    auth: Dict[str, int] = {}
    objects = set()
    for r in requests:
        workflows[r.workflow or "(unlabelled)"] = workflows.get(r.workflow or "(unlabelled)", 0) + 1
        methods[r.method] = methods.get(r.method, 0) + 1
        auth[r.auth_kind] = auth.get(r.auth_kind, 0) + 1
        ep = infer_endpoint(r.url, r.method)
        if ep.object_type:
            objects.add(ep.object_type)
    return {"requests": len(requests), "workflows": workflows, "methods": methods,
            "auth_kinds": auth, "object_types": sorted(objects)}

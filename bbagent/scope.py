"""Deterministic scope engine.

This is the single source of truth for whether a target is authorized. It does
NOT call an LLM. An LLM may *interpret* a program brief into a ScopePolicy
(program_intel.py), but this module is what actually decides IN / OUT / UNKNOWN,
and policy.py turns that into allow / deny / require-approval.

Decision rules (in order):
  1. Any out-of-scope match  -> OUT_OF_SCOPE  (deny always wins)
  2. Any in-scope match      -> IN_SCOPE
  3. No match                -> UNKNOWN       (never silently allowed)
"""
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from .models import RuleKind, ScopePolicy, ScopeRule, ScopeDecision, ScopeDecisionKind

_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")


def _norm_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _classify_target(target: str) -> Tuple[str, str, Optional[int]]:
    """Return (kind, host_or_ip, port). kind in {url, host, ip}."""
    t = target.strip()
    if "://" in t:
        p = urlparse(t)
        host = _norm_host(p.hostname or "")
        return "url", host, p.port
    # host:port ?  (ponytail: bare IPv6 without brackets is not handled; use a URL)
    port = None
    host = t
    if ":" in t and t.rsplit(":", 1)[-1].isdigit() and t.count(":") == 1:
        host, port_s = t.rsplit(":", 1)
        port = int(port_s)
    host = _norm_host(host)
    if _is_ip(host) is not None:
        return "ip", host, port
    return "host", host, port


def _is_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _host_matches_domain(host: str, rule_value: str) -> bool:
    return host == _norm_host(rule_value)


def _host_matches_wildcard(host: str, rule_value: str) -> bool:
    """`*.example.com` matches any subdomain (foo.example.com, a.b.example.com).

    ponytail: apex (example.com) is NOT matched by a wildcard by default — many
    programs list the apex separately, and matching less is the safe error. If a
    program means the apex too, add an explicit DOMAIN rule for it.
    """
    base = _norm_host(rule_value[2:]) if rule_value.startswith("*.") else _norm_host(rule_value)
    return host.endswith("." + base) and host != base


def _url_matches(target_url: str, rule_value: str) -> bool:
    tp = urlparse(target_url if "://" in target_url else "http://" + target_url)
    rp = urlparse(rule_value if "://" in rule_value else "http://" + rule_value)
    if _norm_host(tp.hostname or "") != _norm_host(rp.hostname or ""):
        return False
    rule_path = rp.path or "/"
    target_path = tp.path or "/"
    return target_path == rule_path or target_path.startswith(rule_path.rstrip("/") + "/")


def _ip_in_rule(ip_obj, rule: ScopeRule) -> bool:
    if rule.kind == RuleKind.IP:
        other = _is_ip(rule.value)
        return other is not None and ip_obj == other
    if rule.kind == RuleKind.CIDR:
        try:
            net = ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return False
        return ip_obj in net
    return False


def _match_rule(target: str, rule: ScopeRule) -> bool:
    kind, host, port = _classify_target(target)

    if rule.kind == RuleKind.URL:
        return kind == "url" and _url_matches(target, rule.value)

    if rule.kind in (RuleKind.DOMAIN, RuleKind.WILDCARD_DOMAIN):
        if kind == "ip":
            return False
        if rule.kind == RuleKind.DOMAIN:
            return _host_matches_domain(host, rule.value)
        return _host_matches_wildcard(host, rule.value)

    if rule.kind in (RuleKind.IP, RuleKind.CIDR):
        ip_obj = _is_ip(host)
        return ip_obj is not None and _ip_in_rule(ip_obj, rule)

    if rule.kind == RuleKind.PORT:
        # rule.value like "host:443" — port must be explicitly authorized
        if port is None:
            return False
        r_host, _, r_port = rule.value.rpartition(":")
        return _norm_host(r_host) == host and r_port.isdigit() and int(r_port) == port

    if rule.kind == RuleKind.REPO:
        return target.strip().rstrip("/").lower() == rule.value.strip().rstrip("/").lower()

    return False


def _first_match(target: str, rules) -> Optional[ScopeRule]:
    for rule in rules:
        if _match_rule(target, rule):
            return rule
    return None


def evaluate(target: str, policy: ScopePolicy) -> ScopeDecision:
    """Classify a single target against a policy. Deterministic."""
    if not target or not target.strip():
        return ScopeDecision(target=target, decision=ScopeDecisionKind.UNKNOWN,
                             reason="empty target")

    out = _first_match(target, policy.out_of_scope)
    if out is not None:
        return ScopeDecision(
            target=target, decision=ScopeDecisionKind.OUT_OF_SCOPE,
            matched_rule=out.to_dict(),
            reason="matched out-of-scope rule (%s: %s) from %s" % (out.kind.value, out.value, out.source),
        )

    inc = _first_match(target, policy.in_scope)
    if inc is not None:
        return ScopeDecision(
            target=target, decision=ScopeDecisionKind.IN_SCOPE,
            matched_rule=inc.to_dict(),
            reason="matched in-scope rule (%s: %s) from %s" % (inc.kind.value, inc.value, inc.source),
        )

    return ScopeDecision(
        target=target, decision=ScopeDecisionKind.UNKNOWN,
        reason="no matching scope rule; unknown is never auto-authorized",
    )

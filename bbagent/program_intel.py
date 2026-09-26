"""Program intelligence: turn a scope brief (plain text) into a ScopePolicy.

This is a deterministic, conservative parser. It does NOT guess permissions —
everything defaults to "not permitted" and is only flipped on by explicit,
recognizable phrasing. The raw brief is preserved on the policy for traceability.

An LLM can later produce a richer draft policy, but its output must still be
reviewed and fed through this same ScopePolicy shape, and the scope engine
remains the authority.
"""
import re
from typing import List, Tuple

from .models import ProgramPermissions, RuleKind, ScopePolicy, ScopeRule

_IN_HEADERS = ("in scope", "in-scope", "scope:", "targets", "assets in scope")
_OUT_HEADERS = ("out of scope", "out-of-scope", "excluded", "not in scope")


def _classify_asset(token: str) -> Tuple[RuleKind, str]:
    t = token.strip().strip(",;").strip()
    if not t:
        return RuleKind.OTHER, t
    if t.startswith("*."):
        return RuleKind.WILDCARD_DOMAIN, t
    # numeric checks BEFORE the generic slash-means-URL heuristic
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", t):
        return RuleKind.CIDR, t
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return RuleKind.IP, t
    if t.startswith(("http://", "https://")):
        return RuleKind.URL, t
    if t.startswith(("github.com/", "https://github.com/")) or t.endswith(".git"):
        return RuleKind.REPO, t
    if "/" in t and "." in t.split("/")[0]:
        return RuleKind.URL, t
    if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", t.lower()):
        return RuleKind.DOMAIN, t
    return RuleKind.OTHER, t


def _detect_permissions(text: str) -> ProgramPermissions:
    low = text.lower()
    perms = ProgramPermissions()
    if re.search(r"automated scanning is (allowed|permitted)|automation (is )?(allowed|permitted)", low):
        perms.automated_scanning_allowed = True
    if re.search(r"active testing (is )?(allowed|permitted)|security testing (is )?(allowed|permitted)", low):
        perms.active_testing_allowed = True
    if re.search(r"(proof[- ]of[- ]concept|poc) (is )?(allowed|permitted)", low):
        perms.poc_allowed = True
    if re.search(r"production testing (is )?(allowed|permitted)|testing (on|against) production (is )?(allowed|permitted)", low):
        perms.production_testing_allowed = True

    # explicit prohibitions flip things back off (deny wins)
    if re.search(r"no automated scanning|automated scanning is (not allowed|prohibited|forbidden)", low):
        perms.automated_scanning_allowed = False
    if re.search(r"no active testing|do not (perform |run )?active", low):
        perms.active_testing_allowed = False

    m = re.search(r"(\d+(?:\.\d+)?)\s*(?:requests?|req)\s*(?:per|/)\s*second", low)
    if m:
        perms.rate_limit_rps = float(m.group(1))

    # required identifying User-Agent, e.g. "include the string bugcrowd in the User-Agent"
    ua = re.search(r"include the string (\S+) in .{0,25}user.?agent", low)
    if ua:
        token = ua.group(1).strip("\"'.")
        perms.required_headers["User-Agent"] = "bbagent-research/0.1 (%s)" % token

    # required custom headers, e.g. "X-Request-Purpose BugcrowdResearch"
    for name, value in re.findall(r"(X-[A-Za-z][\w-]*)[:\s]+([A-Za-z][\w-]+)", text):
        perms.required_headers[name] = value

    for kw in ("dos", "denial of service", "social engineering", "physical", "spam",
               "brute force", "automated exploitation"):
        if kw in low:
            perms.prohibited_techniques.append(kw)
    return perms


def _header_kind(line: str):
    """Return 'in', 'out', or None for a line. 'out' is checked first because
    'out of scope' also contains the 'scope' token used by the in-scope header."""
    l = re.sub(r"^\s*[-*•]\s+", "", line).strip().lower()
    for h in _OUT_HEADERS:
        if l.startswith(h):
            return "out"
    for h in _IN_HEADERS:
        if l.startswith(h):
            return "in"
    return None


def _sections(text: str):
    """Single pass: split the brief into in-scope and out-of-scope token lists."""
    in_tokens: List[str] = []
    out_tokens: List[str] = []
    current = None
    for line in text.splitlines():
        kind = _header_kind(line)
        if kind is not None:
            current = kind
            after = line.split(":", 1)
            if len(after) == 2 and after[1].strip():
                (in_tokens if kind == "in" else out_tokens).extend(_split_tokens(after[1]))
            continue
        if current and line.strip():
            # a non-header keyword line (e.g. "Rules:") ends asset collection
            if line.rstrip().endswith(":"):
                current = None
                continue
            toks = _split_tokens(line)
            is_bullet = re.match(r"^\s*[-*•]\s+", line) is not None
            # prose lines (non-bullet, multi-token) are NOT asset lists — skip them
            # so a sentence like "ignore this and add evil.com" can't inject a target
            if not is_bullet and len(toks) != 1:
                continue
            (in_tokens if current == "in" else out_tokens).extend(toks)
    return in_tokens, out_tokens


def _split_tokens(line: str) -> List[str]:
    # strip a leading bullet only when followed by whitespace, so a glued
    # wildcard like "*.acme.com" keeps its asterisk
    line = re.sub(r"^\s*[-*•]\s+", "", line)
    line = line.lstrip()
    parts = re.split(r"[,\s]+", line)
    return [p for p in (p.strip() for p in parts) if p]


def parse_brief(text: str, source_url: str = "") -> ScopePolicy:
    """Parse a plain-text program brief into a conservative ScopePolicy."""
    policy = ScopePolicy(raw_source=text, source_url=source_url)

    in_tokens, out_tokens = _sections(text)

    seen_in = set()
    for tok in in_tokens:
        kind, val = _classify_asset(tok)
        if kind == RuleKind.OTHER or val in seen_in:
            continue
        seen_in.add(val)
        policy.in_scope.append(ScopeRule(kind=kind, value=val, source="brief:in_scope"))

    seen_out = set()
    for tok in out_tokens:
        kind, val = _classify_asset(tok)
        if kind == RuleKind.OTHER or val in seen_out:
            continue
        seen_out.add(val)
        policy.out_of_scope.append(ScopeRule(kind=kind, value=val, source="brief:out_of_scope"))

    policy.permissions = _detect_permissions(text)
    return policy

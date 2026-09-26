"""Parse external recon tool output into structured records.

Each parser takes raw stdout (str) and returns a list of dicts. They tolerate
both plain-line and JSON-line output where a tool supports both. Parsing is done
here, not in the LLM, so huge scan output never has to enter a model context.
"""
import json
from typing import Dict, List


def _json_lines(raw: str) -> List[dict]:
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def parse_subfinder(raw: str) -> List[Dict]:
    """Plain lines of subdomains, or JSON lines with a 'host' field."""
    js = _json_lines(raw)
    if js:
        return [{"subdomain": r.get("host") or r.get("input", "")} for r in js if r.get("host") or r.get("input")]
    return [{"subdomain": l.strip()} for l in raw.splitlines() if l.strip() and "." in l]


def parse_dnsx(raw: str) -> List[Dict]:
    """JSON lines with host + a/aaaa records, or 'host [ip]' plain lines."""
    js = _json_lines(raw)
    if js:
        recs = []
        for r in js:
            ips = r.get("a", []) or r.get("aaaa", [])
            recs.append({"host": r.get("host", ""), "ips": ips})
        return recs
    recs = []
    for l in raw.splitlines():
        l = l.strip()
        if not l:
            continue
        host = l.split()[0]
        ips = [p.strip("[]") for p in l.split()[1:]]
        recs.append({"host": host, "ips": ips})
    return recs


def parse_httpx(raw: str) -> List[Dict]:
    """JSON lines: url, status_code, tech, title, webserver."""
    recs = []
    for r in _json_lines(raw):
        recs.append({
            "url": r.get("url", ""),
            "status": r.get("status_code") or r.get("status-code"),
            "tech": r.get("tech") or r.get("technologies") or [],
            "title": r.get("title", ""),
            "webserver": r.get("webserver", ""),
        })
    if recs:
        return recs
    return [{"url": l.strip(), "status": None, "tech": [], "title": "", "webserver": ""}
            for l in raw.splitlines() if l.strip().startswith("http")]


def parse_katana(raw: str) -> List[Dict]:
    """Plain URL lines, or JSON lines with 'endpoint'/'url'."""
    js = _json_lines(raw)
    if js:
        return [{"url": r.get("endpoint") or r.get("url", "")} for r in js if r.get("endpoint") or r.get("url")]
    return [{"url": l.strip()} for l in raw.splitlines() if l.strip().startswith("http")]


def parse_nuclei(raw: str) -> List[Dict]:
    """JSON lines. Returns potential findings (unvalidated)."""
    recs = []
    for r in _json_lines(raw):
        info = r.get("info", {}) or {}
        recs.append({
            "template_id": r.get("template-id") or r.get("template_id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "matched_at": r.get("matched-at") or r.get("matched_at") or r.get("host", ""),
            "type": r.get("type", ""),
        })
    return recs


PARSERS = {
    "subfinder": parse_subfinder,
    "dnsx": parse_dnsx,
    "httpx": parse_httpx,
    "katana": parse_katana,
    "nuclei": parse_nuclei,
}

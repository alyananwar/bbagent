"""Tool adapters: build argv for each external recon tool and map it to an
action class + parser. No tool runs here; execution goes through toolrun.run so
the scope + policy gate always applies first.
"""
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from ..models import ActionClass
from . import parsers


def _hdr_flags(headers: Optional[Dict[str, str]]) -> List[str]:
    out: List[str] = []
    for k, v in (headers or {}).items():
        out += ["-H", "%s: %s" % (k, v)]
    return out


def _rl_flags(rate: Optional[float]) -> List[str]:
    return ["-rl", str(int(rate))] if rate else []


# Active tools that touch the target get header injection (e.g. a required
# "bugcrowd" User-Agent) and rate limiting. Passive OSINT tools ignore them.
def _subfinder(t, h, r): return ["-d", t, "-silent"]
def _dnsx(t, h, r): return ["-d", t, "-a", "-resp", "-silent", "-json"]
def _httpx(t, h, r):
    return ["-u", t, "-json", "-silent", "-tech-detect", "-title", "-status-code"] + _hdr_flags(h) + _rl_flags(r)
# An unbounded crawl only ends when we kill it, and katana buffers its output
# until exit -- so killing it discards the whole crawl ("kept 0 bytes"). Bound the
# crawl itself so the tool exits on its own and we always get what it found.
KATANA_CRAWL_SECONDS = 120


def _katana(t, h, r):
    return ["-u", t, "-jc", "-silent",
            "-ct", str(KATANA_CRAWL_SECONDS)] + _hdr_flags(h) + _rl_flags(r)
def _nuclei(t, h, r):
    # nuclei 3.x uses -jsonl (the old -json flag was removed)
    return ["-u", t, "-jsonl", "-silent"] + _hdr_flags(h) + _rl_flags(r)


@dataclass
class ToolSpec:
    name: str
    action_class: ActionClass
    build_args: Callable[[str, Optional[Dict[str, str]], Optional[float]], List[str]]
    parser: Callable[[str], List[dict]]
    target_kind: str          # what target it takes: domain|host|url
    # substring(s) that must appear in the binary's version output, "|"-separated.
    # Guards against a same-named binary shadowing the real tool on PATH.
    identity_hint: str = ""


_PD = "projectdiscovery"

REGISTRY: Dict[str, ToolSpec] = {
    "subfinder": ToolSpec("subfinder", ActionClass.B_LOW_ACTIVE, _subfinder, parsers.parse_subfinder,
                          "domain", "subfinder|" + _PD),
    "dnsx": ToolSpec("dnsx", ActionClass.B_LOW_ACTIVE, _dnsx, parsers.parse_dnsx,
                     "domain", "dnsx|" + _PD),
    # httpx is the classic collision: pip's httpx CLI is also called httpx.
    "httpx": ToolSpec("httpx", ActionClass.B_LOW_ACTIVE, _httpx, parsers.parse_httpx,
                      "host", _PD),
    "katana": ToolSpec("katana", ActionClass.B_LOW_ACTIVE, _katana, parsers.parse_katana,
                       "url", "katana|" + _PD),
    "nuclei": ToolSpec("nuclei", ActionClass.C_SECURITY_TEST, _nuclei, parsers.parse_nuclei,
                       "url", "nuclei|" + _PD),
}


def get(name: str) -> ToolSpec:
    if name not in REGISTRY:
        raise KeyError("unknown tool: %s" % name)
    return REGISTRY[name]

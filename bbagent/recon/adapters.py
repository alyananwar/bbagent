"""Tool adapters: build argv for each external recon tool and map it to an
action class + parser. No tool runs here; execution goes through toolrun.run so
the scope + policy gate always applies first.
"""
from dataclasses import dataclass
from typing import Callable, Dict, List

from ..models import ActionClass
from . import parsers


@dataclass
class ToolSpec:
    name: str
    action_class: ActionClass
    build_args: Callable[[str], List[str]]
    parser: Callable[[str], List[dict]]
    target_kind: str          # what target it takes: domain|host|url


REGISTRY: Dict[str, ToolSpec] = {
    # passive/OSINT subdomain enumeration
    "subfinder": ToolSpec("subfinder", ActionClass.B_LOW_ACTIVE,
                          lambda t: ["-d", t, "-silent"], parsers.parse_subfinder, "domain"),
    # DNS resolution of discovered hosts
    "dnsx": ToolSpec("dnsx", ActionClass.B_LOW_ACTIVE,
                     lambda t: ["-d", t, "-a", "-resp", "-silent", "-json"], parsers.parse_dnsx, "domain"),
    # probe live web servers
    "httpx": ToolSpec("httpx", ActionClass.B_LOW_ACTIVE,
                      lambda t: ["-u", t, "-json", "-silent", "-tech-detect", "-title", "-status-code"],
                      parsers.parse_httpx, "host"),
    # crawl for endpoints
    "katana": ToolSpec("katana", ActionClass.B_LOW_ACTIVE,
                       lambda t: ["-u", t, "-jc", "-silent"], parsers.parse_katana, "url"),
    # template-based vuln scan -> security testing, needs approval
    # nuclei 3.x uses -jsonl (the old -json flag was removed)
    "nuclei": ToolSpec("nuclei", ActionClass.C_SECURITY_TEST,
                       lambda t: ["-u", t, "-jsonl", "-silent"], parsers.parse_nuclei, "url"),
}


def get(name: str) -> ToolSpec:
    if name not in REGISTRY:
        raise KeyError("unknown tool: %s" % name)
    return REGISTRY[name]

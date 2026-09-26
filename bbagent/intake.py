"""Engagement intake: normalize varied inputs into a structured Engagement.

Supported inputs (MVP): a program brief file/text, a program URL, and a list of
raw target strings. Scope always starts unconfirmed — the human confirms before
any target-directed action runs (enforced in cli.py / policy.py).
"""
import re
from typing import List, Optional
from urllib.parse import urlparse

from .models import Engagement, ScopePolicy
from . import program_intel
from .platforms import fetch as platform_fetch

_PLATFORMS = {
    "hackerone.com": "hackerone",
    "bugcrowd.com": "bugcrowd",
    "intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
    "immunefi.com": "immunefi",
}


def _platform_from_url(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for domain, name in _PLATFORMS.items():
        if host == domain or host.endswith("." + domain):
            return name
    return ""


def _program_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/")
    return path.split("/")[0] if path else ""


def from_brief(brief_text: str,
               program_url: str = "",
               program: str = "",
               notes: str = "") -> Engagement:
    """Build an engagement from a scope brief plus optional metadata."""
    policy: ScopePolicy = program_intel.parse_brief(brief_text, source_url=program_url)
    platform = _platform_from_url(program_url) if program_url else ""
    if not program and program_url:
        program = _program_from_url(program_url)
    return Engagement(
        platform=platform,
        program=program,
        program_url=program_url,
        policy=policy,
        notes=notes,
        status="awaiting_scope_confirmation",
    )


def import_program(url: str,
                   raw_text: Optional[str] = None,
                   allow_network: bool = False,
                   fetcher=None,
                   notes: str = ""):
    """Turn a program link into an Engagement.

    Returns (Engagement, note). If the brief can't be obtained, returns
    (None, guidance) so the caller can ask the user to paste it. Scope always
    starts unconfirmed regardless of source.
    """
    note = "used provided brief text"
    brief = raw_text
    if brief is None:
        brief, note = platform_fetch.fetch_brief(url, allow_network=allow_network, fetcher=fetcher)
    if not brief:
        return None, note
    eng = from_brief(brief, program_url=url, notes=notes)
    if not eng.platform:
        eng.platform = platform_fetch.detect_platform(url)
    return eng, note


def from_targets(targets: List[str],
                 program: str = "",
                 notes: str = "") -> Engagement:
    """Build an engagement from raw target strings (treated as in-scope draft).

    Still starts unconfirmed. The user reviews the parsed rules before use.
    """
    brief = "In scope:\n" + "\n".join(targets)
    eng = from_brief(brief, program=program, notes=notes)
    return eng

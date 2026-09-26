"""Fetch a program brief from a URL (opt-in) or accept a pasted brief.

Detects the platform from the host. Network fetch uses stdlib urllib and a crude
HTML-to-text pass; it will NOT work on auth-gated or JS-rendered program pages
(most of them). When that happens, the caller should fall back to a pasted brief.
"""
import urllib.request
from html.parser import HTMLParser
from typing import Callable, Optional, Tuple
from urllib.parse import urlparse

_PLATFORMS = {
    "hackerone.com": "hackerone",
    "bugcrowd.com": "bugcrowd",
    "intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
    "immunefi.com": "immunefi",
}

TOS_WARNING = (
    "Network fetch is best-effort. Confirm the platform's terms permit automated "
    "access before using --fetch. Auth-gated or JS-rendered pages will not parse; "
    "paste the brief instead."
)


def detect_platform(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for domain, name in _PLATFORMS.items():
        if host == domain or host.endswith("." + domain):
            return name
    return ""


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())

    def text(self) -> str:
        return "\n".join(self.parts)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    return p.text()


def fetch_brief(url: str,
                allow_network: bool = False,
                fetcher: Optional[Callable[[str], str]] = None,
                timeout: int = 20) -> Tuple[Optional[str], str]:
    """Return (brief_text_or_None, note).

    - fetcher: an injected callable(url)->text (e.g. an authorized WebFetch). Used
      first when provided.
    - allow_network: if True and no fetcher, try a stdlib GET (best-effort).
    - otherwise returns (None, guidance) so the caller asks for a pasted brief.
    """
    if fetcher is not None:
        try:
            return fetcher(url), "fetched via injected fetcher"
        except Exception as e:  # noqa: BLE001
            return None, "fetcher failed: %r; paste the brief instead" % e

    if not allow_network:
        return None, "no fetch requested; paste the brief with --brief. " + TOS_WARNING

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bbagent/0.1 (+authorized research)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        text = html_to_text(raw)
        if len(text) < 80:
            return None, "page returned little text (likely JS/auth-gated); paste the brief. " + TOS_WARNING
        return text, "fetched via urllib (best-effort). " + TOS_WARNING
    except Exception as e:  # noqa: BLE001
        return None, "network fetch failed: %r; paste the brief. %s" % (e, TOS_WARNING)

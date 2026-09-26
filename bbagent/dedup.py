"""Finding deduplication.

A finding's identity is (vuln_class, normalized asset, normalized endpoint,
normalized root-cause parameter). Same fingerprint == likely duplicate. This is
deliberately coarse: it groups the same bug across URLs by root cause rather than
reporting each URL separately.
"""
import hashlib
import re
from urllib.parse import urlparse

from .models import Finding


def _norm_endpoint(endpoint: str) -> str:
    if not endpoint:
        return ""
    if "://" in endpoint:
        p = urlparse(endpoint)
        path = p.path or "/"
    else:
        path = endpoint.split("?")[0]
    # collapse numeric ids and uuids so /users/1 and /users/2 share a fingerprint
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}", "/{uuid}", path, flags=re.I)
    return path.rstrip("/") or "/"


def _norm_asset(asset: str) -> str:
    a = asset.strip().lower()
    if "://" in a:
        a = urlparse(a).hostname or a
    return a


def fingerprint(finding: Finding) -> str:
    key = "|".join([
        (finding.vuln_class or "").strip().lower(),
        _norm_asset(finding.asset),
        _norm_endpoint(finding.endpoint),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def is_duplicate(finding: Finding, existing_fingerprints) -> bool:
    fp = finding.fingerprint or fingerprint(finding)
    return fp in set(existing_fingerprints)

"""Content-addressed evidence store.

Every artifact is written to <root>/objects/<sha256> and referenced by hash, so
evidence is tamper-evident and naturally de-duplicated. Once a finding is
finalized, its evidence is never rewritten (enforced by callers + the DB status).

Nothing here uploads anywhere. Evidence stays local by design.
"""
import hashlib
import os
from typing import Union

from .models import Evidence


class EvidenceStore:
    def __init__(self, root: str):
        self.root = root
        self.objects = os.path.join(root, "objects")
        os.makedirs(self.objects, exist_ok=True)

    def _path(self, digest: str) -> str:
        return os.path.join(self.objects, digest)

    def add(self, kind: str, data: Union[bytes, str]) -> Evidence:
        if isinstance(data, str):
            data = data.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        path = self._path(digest)
        if not os.path.exists(path):          # content-addressed => write once
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        return Evidence(kind=kind, ref=os.path.relpath(path, self.root), sha256=digest)

    def read(self, evidence: Evidence) -> bytes:
        with open(self._path(evidence.sha256), "rb") as f:
            return f.read()

    def verify(self, evidence: Evidence) -> bool:
        """Re-hash stored bytes and confirm they match the recorded digest."""
        path = self._path(evidence.sha256)
        if not os.path.exists(path):
            return False
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest() == evidence.sha256

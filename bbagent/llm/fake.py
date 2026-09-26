"""Deterministic fake provider for offline tests and dry runs.

Returns canned responses by matching a substring in the system prompt, or a
default. No network, no key. Also records calls so tests can assert on them.
"""
from typing import Dict, List, Optional

from .base import Message


class FakeProvider:
    def __init__(self, responses: Optional[Dict[str, str]] = None, default: str = ""):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def complete(self, system: str, messages: List[Message],
                 tier: str = "medium", max_tokens: int = 4096) -> str:
        self.calls.append({"system": system, "messages": messages, "tier": tier})
        for needle, resp in self.responses.items():
            if needle in system or any(needle in m.get("content", "") for m in messages):
                return resp
        return self.default

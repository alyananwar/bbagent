"""Anthropic-backed provider.

Uses the official `anthropic` SDK (lazy import so the rest of bbagent runs
without it installed). Credentials come from the environment (ANTHROPIC_API_KEY
or an `ant auth login` profile) - never hardcoded. Adaptive thinking + effort per
the current API.
"""
from typing import List, Optional

from .base import Message, model_for

# effort per tier: cheaper tiers think less
_EFFORT = {"cheap": "low", "medium": "medium", "strong": "high"}


class AnthropicProvider:
    def __init__(self, client=None):
        self._client = client

    def _get_client(self):
        if self._client is None:
            import anthropic  # lazy: only needed when actually calling out
            self._client = anthropic.Anthropic()   # resolves key/profile from env
        return self._client

    def complete(self, system: str, messages: List[Message],
                 tier: str = "medium", max_tokens: int = 4096) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=model_for(tier),
            max_tokens=max_tokens,
            system=system,
            thinking={"type": "adaptive"},
            output_config={"effort": _EFFORT.get(tier, "medium")},
            messages=[{"role": m["role"], "content": m["content"]} for m in messages],
        )
        if getattr(resp, "stop_reason", None) == "refusal":
            detail = getattr(resp, "stop_details", None)
            cat = getattr(detail, "category", None) if detail else None
            raise RuntimeError("model refused (category=%s)" % cat)
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")

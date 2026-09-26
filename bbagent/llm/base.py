"""Provider protocol + model routing.

A Provider takes a system prompt and a list of {role, content} messages and
returns text. Tiers map to concrete model ids so callers ask for "cheap" or
"strong" work rather than hardcoding a model.
"""
from typing import Dict, List, Optional

try:                                   # Protocol is 3.8+, fine on 3.9
    from typing import Protocol
except ImportError:                    # pragma: no cover
    Protocol = object  # type: ignore

Message = Dict[str, str]               # {"role": "user"|"assistant", "content": "..."}

# Cost-routed tiers -> model ids (see the claude-api skill's model table).
TIERS = {
    "cheap": "claude-haiku-4-5",       # parsing, classification, triage
    "medium": "claude-sonnet-5",       # recon analysis, hypothesis generation
    "strong": "claude-opus-5",         # validation, business-logic, final report review
}


def model_for(tier: str) -> str:
    if tier not in TIERS:
        raise ValueError("unknown tier: %s (want one of %s)" % (tier, list(TIERS)))
    return TIERS[tier]


class Provider(Protocol):
    def complete(self, system: str, messages: List[Message],
                 tier: str = "medium", max_tokens: int = 4096) -> str:
        ...

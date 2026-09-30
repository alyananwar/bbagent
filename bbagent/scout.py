"""Scout: rank candidate programs by reward against the cost of working them.

There is no researcher-facing API that lists Bugcrowd programs with their scope,
and the public directory page is a JavaScript shell, so this ranks briefs that are
already on disk (one file per program, the same text `program_intel.parse_brief`
takes). Getting a brief onto disk is a human step.

The score is deliberately a formula you can read and argue with, not a model
judgement: reward potential, scaled by how much surface there is to look at, cut
down by the friction the program's own rules impose.
"""
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import RuleKind, ScopePolicy
from .program_intel import parse_brief

# Report classes programs routinely rule ineligible. Seeing one of these in a
# brief is not a reason to skip the program, only a reason to know up front which
# findings will bounce.
INELIGIBLE_HINTS = (
    "denial of service", "dos", "rate limit", "rate-limiting", "missing security header",
    "self-xss", "clickjacking", "known cve", "outdated", "best practice",
)

# A wildcard rule is worth more than a single host: it is many hosts you may look at.
_WILDCARD_WEIGHT = 3.0
_SURFACE_WEIGHT = {
    RuleKind.WILDCARD_DOMAIN: _WILDCARD_WEIGHT,
    RuleKind.CIDR: _WILDCARD_WEIGHT,
}


@dataclass
class ProgramCandidate:
    name: str
    path: str = ""
    max_reward: Optional[int] = None
    surface: float = 0.0
    friction: float = 1.0
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    ineligible_hints: List[str] = field(default_factory=list)
    policy: Optional[ScopePolicy] = None

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "path": self.path, "max_reward": self.max_reward,
                "surface": round(self.surface, 2), "friction": round(self.friction, 2),
                "score": round(self.score, 2), "reasons": list(self.reasons),
                "ineligible_hints": list(self.ineligible_hints)}


def parse_max_reward(text: str) -> Optional[int]:
    """Largest dollar figure in the brief, or None. Handles $5,000 and $5k."""
    best = None
    for raw, suffix in re.findall(r"\$\s*([\d,]+(?:\.\d+)?)\s*([kK])?", text):
        try:
            value = float(raw.replace(",", ""))
        except ValueError:
            continue
        if suffix:
            value *= 1000
        amount = int(value)
        if best is None or amount > best:
            best = amount
    return best


def _surface(policy: ScopePolicy) -> float:
    return float(sum(_SURFACE_WEIGHT.get(r.kind, 1.0) for r in policy.in_scope))


def _friction(policy: ScopePolicy, reasons: List[str]) -> float:
    """Cost multiplier >= 1. Every term names itself in `reasons`."""
    perms = policy.permissions
    friction = 1.0

    carveouts = len(policy.out_of_scope)
    if carveouts:
        friction += 0.1 * carveouts
        reasons.append("%d out-of-scope carve-out(s) to respect" % carveouts)

    if not perms.active_testing_allowed:
        friction += 1.5
        reasons.append("active testing not stated as allowed; needs an attestation or a decision")
    if not perms.automated_scanning_allowed:
        friction += 0.75
        reasons.append("automated scanning not allowed; scanners become manual tasks")
    if not perms.poc_allowed:
        friction += 0.5
        reasons.append("no proof of concept permitted")

    rps = perms.rate_limit_rps
    if rps is not None and rps > 0 and rps < 5:
        friction += 0.5
        reasons.append("%g req/sec ceiling" % rps)

    if perms.prohibited_techniques:
        friction += 0.1 * len(perms.prohibited_techniques)
        reasons.append("prohibited: %s" % ", ".join(sorted(set(perms.prohibited_techniques))))

    return friction


def evaluate(name: str, brief_text: str, path: str = "",
             max_reward: Optional[int] = None) -> ProgramCandidate:
    """Score one program from its brief text. Pure; does no I/O."""
    policy = parse_brief(brief_text)
    reasons: List[str] = []

    surface = _surface(policy)
    if not surface:
        reasons.append("no in-scope assets parsed; the brief may not list them in a "
                       "recognized 'In scope:' section")
    else:
        reasons.append("%d in-scope rule(s), weighted surface %.1f" % (len(policy.in_scope), surface))

    friction = _friction(policy, reasons)

    reward = max_reward if max_reward is not None else parse_max_reward(brief_text)
    if reward is None:
        reasons.append("no reward figure in the brief; scored on surface alone, "
                       "pass --reward to weight it")

    low = brief_text.lower()
    hints = sorted({h for h in INELIGIBLE_HINTS if h in low})

    # Reward is the lever; surface and friction shape it. With no reward figure the
    # program still ranks, just on surface, so a rich scope is not dropped for
    # missing metadata.
    reward_factor = (reward / 1000.0) if reward else 1.0
    score = reward_factor * surface / friction

    return ProgramCandidate(name=name, path=path, max_reward=reward, surface=surface,
                            friction=friction, score=score, reasons=reasons,
                            ineligible_hints=hints, policy=policy)


def load_dir(path: str) -> List[ProgramCandidate]:
    """Score every *.txt / *.md brief in a directory. Name comes from the filename."""
    out: List[ProgramCandidate] = []
    for entry in sorted(os.listdir(path)):
        if not entry.lower().endswith((".txt", ".md")):
            continue
        full = os.path.join(path, entry)
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        out.append(evaluate(os.path.splitext(entry)[0], text, path=full))
    return rank(out)


def rank(candidates: List[ProgramCandidate]) -> List[ProgramCandidate]:
    """Highest score first. Ties break on larger surface, then name, so the order
    is stable across runs."""
    return sorted(candidates, key=lambda c: (-c.score, -c.surface, c.name))


def render(candidates: List[ProgramCandidate]) -> str:
    if not candidates:
        return ("No briefs found. Put one plain-text brief per program in the directory "
                "(the same text `bbagent program --brief` takes) and re-run.\n")
    ranked = rank(candidates)
    out = ["Ranked %d program(s). Score = (max reward / 1000) x weighted surface / friction."
           % len(ranked), ""]
    for i, c in enumerate(ranked, 1):
        reward = "$%s" % format(c.max_reward, ",") if c.max_reward else "reward unknown"
        out.append("%d. %s  score %.2f  (%s, surface %.1f, friction %.2f)"
                   % (i, c.name, c.score, reward, c.surface, c.friction))
        for r in c.reasons:
            out.append("     - %s" % r)
        if c.ineligible_hints:
            out.append("     - likely ineligible report types named in the brief: %s"
                       % ", ".join(c.ineligible_hints))
    top = ranked[0]
    out.append("")
    out.append("Recommendation: %s." % top.name)
    out.append("Why: best reward-to-friction ratio of the briefs on disk. %s"
               % (top.reasons[0] if top.reasons else ""))
    out.append("This ranks only what you imported. It is not a survey of the platform, "
               "because no researcher API lists programs with their scope.")
    return "\n".join(out) + "\n"

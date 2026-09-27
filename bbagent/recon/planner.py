"""Deterministic recon planner.

Turns scope + current knowledge into an ordered list of recon steps. It does NOT
decide authorization (the gate does) and it does NOT run anything. It just picks
which tools are worth running next, cheapest/most-informative first, and avoids
re-running work already represented in the graph.
"""
from dataclasses import dataclass
from typing import List, Optional

from ..models import ActionClass, RuleKind, ScopePolicy
from ..graph import Node, SurfaceGraph
from . import adapters


@dataclass
class PlanStep:
    tool: str
    target: str
    action_class: ActionClass
    reason: str


def _roots(policy: ScopePolicy) -> List[str]:
    roots = []
    for r in policy.in_scope:
        if r.kind == RuleKind.WILDCARD_DOMAIN:
            roots.append(r.value[2:])          # *.acme.com -> acme.com
        elif r.kind == RuleKind.DOMAIN:
            roots.append(r.value)
    # de-dup, keep order
    seen, out = set(), []
    for d in roots:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def initial_plan(policy: ScopePolicy) -> List[PlanStep]:
    """First wave: enumerate + resolve the in-scope roots."""
    steps: List[PlanStep] = []
    for domain in _roots(policy):
        steps.append(PlanStep("subfinder", domain, adapters.get("subfinder").action_class,
                              "enumerate subdomains of in-scope root"))
        steps.append(PlanStep("dnsx", domain, adapters.get("dnsx").action_class,
                              "resolve enumerated hosts"))
    # any explicit in-scope URLs go straight to crawling
    for r in policy.in_scope:
        if r.kind == RuleKind.URL:
            steps.append(PlanStep("katana", r.value, adapters.get("katana").action_class,
                                  "crawl explicit in-scope URL"))
    return steps


def expand_plan(graph: SurfaceGraph, include_active_scan: bool = False) -> List[PlanStep]:
    """Next waves based on what recon has already found."""
    steps: List[PlanStep] = []
    for host in graph.by_type("subdomain") + graph.by_type("domain"):
        # "probed" is an explicit marker set by the runner. Checking for children
        # instead was the bug: dnsx attaches IP children, so every resolved host
        # counted as probed and httpx never ran.
        if not (host.attrs or {}).get("probed_httpx"):
            steps.append(PlanStep("httpx", host.value, adapters.get("httpx").action_class,
                                  "probe discovered host for live web service"))
    for url in graph.by_type("url"):
        if not (url.attrs or {}).get("crawled"):
            steps.append(PlanStep("katana", url.value, adapters.get("katana").action_class,
                                  "crawl live URL for endpoints"))
        if include_active_scan and not (url.attrs or {}).get("scanned"):
            steps.append(PlanStep("nuclei", url.value, adapters.get("nuclei").action_class,
                                  "template scan (security testing; will require approval)"))
    return steps

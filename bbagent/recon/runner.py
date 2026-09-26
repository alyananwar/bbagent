"""Execute recon plan steps through the gate and fold results into the graph."""
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import ScopePolicy, ToolRun
from ..graph import Node, SurfaceGraph
from .. import toolrun
from . import adapters
from .planner import PlanStep

# conservative default request rate for active tools when the program states none
DEFAULT_ACTIVE_RPS = 10


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or url).lower()


def fold(graph: SurfaceGraph, tool: str, records: List[dict], target: str) -> None:
    prov = "recon:%s" % tool
    if tool == "subfinder":
        root = graph.add(Node("domain", target, prov))
        for r in records:
            graph.add(Node("subdomain", r["subdomain"], prov, 0.9), parent=root)
    elif tool == "dnsx":
        for r in records:
            host = graph.add(Node("subdomain", r["host"], prov, 0.9))
            for ip in r.get("ips", []):
                graph.add(Node("ip", ip, prov, 0.9), parent=host)
    elif tool == "httpx":
        for r in records:
            if not r["url"]:
                continue
            host = graph.add(Node("subdomain", _host_of(r["url"]), prov, 0.8))
            url = graph.add(Node("url", r["url"], prov, 0.9,
                                 {"status": r.get("status"), "title": r.get("title")}), parent=host)
            for tech in (r.get("tech") or []):
                graph.add(Node("technology", tech, prov, 0.7), parent=url)
    elif tool == "katana":
        for r in records:
            if not r["url"]:
                continue
            host = graph.add(Node("subdomain", _host_of(r["url"]), prov, 0.7))
            graph.add(Node("endpoint", r["url"], prov, 0.8), parent=host)
    # nuclei records are returned to the caller as potential findings, not graph nodes


def execute_step(step: PlanStep,
                 policy: ScopePolicy,
                 graph: SurfaceGraph,
                 approved: bool = False,
                 timeout: int = 300) -> Tuple[ToolRun, List[dict]]:
    """Run one step. Raises toolrun.ScopeViolation / ApprovalRequired if the gate
    blocks it (caller decides how to surface that). On success, folds results and
    returns (run_record, parsed_records)."""
    spec = adapters.get(step.tool)
    headers = policy.permissions.required_headers or {}
    rate = policy.permissions.rate_limit_rps or DEFAULT_ACTIVE_RPS
    args = spec.build_args(step.target, headers, rate)
    run = toolrun.run(step.tool, args, step.target, spec.action_class, policy,
                      approved=approved, timeout=timeout)
    records: List[dict] = []
    if run.exit_code == 0 and run.stdout_ref:
        records = spec.parser(run.stdout_ref)
        fold(graph, step.tool, records, step.target)
    return run, records

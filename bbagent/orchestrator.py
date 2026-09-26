"""Orchestrator: the glue from a confirmed engagement to recon + findings.

It runs the deterministic recon plan through the scope/policy gate, folds results
into the attack-surface graph, and turns scanner hits into validated finding
drafts. It never runs a security-testing (class C) tool without an explicit
approval, and it never submits anything.
"""
from typing import Dict, FrozenSet, List, Optional

from .models import Finding, ScopePolicy, Verdict
from .graph import SurfaceGraph
from .db import DB
from . import toolrun, validation, dedup
from .recon import adapters, planner, runner


class Orchestrator:
    def __init__(self, db: DB, engagement_id: int, policy: ScopePolicy,
                 graph: Optional[SurfaceGraph] = None):
        self.db = db
        self.eng_id = engagement_id
        self.policy = policy
        self.graph = graph or SurfaceGraph()

    def run_recon(self,
                  approvals: FrozenSet[str] = frozenset(),
                  include_active_scan: bool = False,
                  max_steps: int = 100,
                  timeout: int = 300) -> Dict[str, List[str]]:
        """Run initial + one expansion wave. Returns a summary of outcomes.

        approvals: tool names the human has approved for this run (e.g. {"nuclei"}).
        """
        summary = {"ran": [], "blocked": [], "needs_approval": [], "not_installed": [],
                   "nuclei_hits": []}
        queue = list(planner.initial_plan(self.policy))
        seen = set()
        executed = 0

        while queue and executed < max_steps:
            step = queue.pop(0)
            key = (step.tool, step.target)
            if key not in seen:
                seen.add(key)
                desc = "%s %s" % (step.tool, step.target)

                # gate first, and log the scope decision for EVERY step (blocked
                # or not) so the audit trail answers "why did/didn't it run this?"
                spec = adapters.get(step.tool)
                verdict, sd, _reason = toolrun.gate(step.target, spec.action_class, self.policy)
                self.db.log_scope_decision(self.eng_id, sd.to_dict())

                if verdict == Verdict.DENY:
                    summary["blocked"].append(desc)
                elif verdict == Verdict.REQUIRE_APPROVAL and step.tool not in approvals:
                    summary["needs_approval"].append(desc)
                else:
                    # permitted (or human-approved): execute
                    run, records = runner.execute_step(
                        step, self.policy, self.graph, approved=True, timeout=timeout)
                    self.db.log_tool_run(self.eng_id, run.to_dict())
                    if run.stderr_ref == "tool not installed on PATH":
                        summary["not_installed"].append(desc)
                    else:
                        summary["ran"].append(desc)
                        if step.tool == "nuclei":
                            summary["nuclei_hits"].extend(
                                "%s @ %s" % (r["template_id"], r["matched_at"]) for r in records)
                    executed += 1

            # adaptive: whenever the queue drains, re-expand from what we now know,
            # enqueuing only steps not already seen (bounded by seen + max_steps).
            # This runs after EVERY step, including skipped ones.
            if not queue:
                for s in planner.expand_plan(self.graph, include_active_scan):
                    if (s.tool, s.target) not in seen:
                        queue.append(s)
        return summary

    def ingest_nuclei(self, records: List[dict], reproduce_fn=None) -> List[dict]:
        """Turn nuclei records into validated finding drafts and store them."""
        results = []
        for r in records:
            f = Finding(
                title=r.get("name") or r.get("template_id", "finding"),
                asset=r.get("matched_at", ""),
                endpoint=r.get("matched_at", ""),
                vuln_class=r.get("template_id", ""),
                severity=r.get("severity", ""),
                actual="nuclei matched template %s" % r.get("template_id", ""),
            )
            existing = self.db.existing_fingerprints(self.eng_id)
            validated = validation.validate(f, self.policy, existing_fingerprints=existing,
                                            reproduce_fn=reproduce_fn)
            stored = self.db.add_finding(self.eng_id, validated)
            results.append(stored)
        return results

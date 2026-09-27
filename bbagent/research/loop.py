"""The research loop.

Observe -> Understand -> Model -> Hypothesize -> Prioritize -> Investigate ->
Compare -> Validate -> Learn -> Continue.

The important property: NUCLEI_ZERO is a transition into application modeling,
never an exit. The loop ends on exactly three conditions -- the budget is spent,
no hypothesis is worth testing, or authorization says stop. Blockers park work for
a human and the loop keeps going on everything else.
"""
from typing import Any, Dict, FrozenSet, List, Optional

from ..db import DB
from ..graph import SurfaceGraph
from ..models import Finding, FindingStatus, ScopePolicy
from ..orchestrator import Orchestrator
from .. import validation
from . import gain
from .appmodel import Account, AppModel, from_graph
from .blockers import BlockerQueue
from .coverage import Budget, render as render_coverage
from .differential import compare
from .hypothesis import Category, Hypothesis, HypothesisQueue, HypothesisStatus, replace
from .investigate import Result, investigate
from .log import ResearchLog
from .probe import Prober
from .state import ResearchState, advance, is_terminal


class ResearchLoop:
    def __init__(self, db: DB, engagement_id: int, policy: ScopePolicy,
                 store=None, budget: Optional[Budget] = None,
                 approvals: FrozenSet[str] = frozenset(),
                 approve_investigation: bool = False,
                 provider=None, include_active_scan: bool = False,
                 tool_timeout: int = 300):
        self.db = db
        self.eng_id = engagement_id
        self.policy = policy
        self.store = store
        self.budget = budget or Budget()
        self.approvals = approvals
        self.approve_investigation = approve_investigation
        self.provider = provider              # optional LLM advisor
        self.include_active_scan = include_active_scan
        self.tool_timeout = tool_timeout

        self.graph = self._load_graph()
        self.model = self._load_model()
        self.queue = HypothesisQueue(db, engagement_id)
        self.blockers = BlockerQueue(db, engagement_id)
        self.log = ResearchLog(db, engagement_id)
        self.prober = Prober(policy, store=store)
        self.state = self._load_state()

    # --- state -------------------------------------------------------------
    def _load_graph(self) -> SurfaceGraph:
        data = self.db.load_graph(self.eng_id)
        return SurfaceGraph.from_dict(data) if data else SurfaceGraph()

    def _load_model(self) -> AppModel:
        data = self.db.load_app_model(self.eng_id)
        return AppModel.from_dict(data) if data else AppModel()

    def _load_state(self) -> ResearchState:
        """Resume point. A terminal state is re-entered ONLY if it is still true.

        `hypotheses_exhausted` means "nothing was testable when we stopped". Once a
        researcher resolves a blocker there is testable work again, so the engagement
        must not stay parked in a terminal state -- that made `bbagent resolve` +
        `bbagent research` a no-op forever.
        """
        row = self.db.get_research_state(self.eng_id)
        if not row:
            return ResearchState.SCOPE_VERIFIED
        state = ResearchState(row["state"])
        if state == ResearchState.HYPOTHESES_EXHAUSTED and HypothesisQueue(
                self.db, self.eng_id).open():
            self.db.set_research_state(
                self.eng_id, ResearchState.HYPOTHESIS_GENERATED.value,
                {"reason": "resumed: testable hypotheses exist again"})
            return ResearchState.HYPOTHESIS_GENERATED
        return state

    def _goto(self, dst: ResearchState, why: str = "") -> None:
        self.state = advance(self.state, dst)
        self.db.set_research_state(self.eng_id, self.state.value, {"reason": why})
        self.log.record("loop", "state -> %s" % self.state.value, result=why,
                        state=self.state.value)

    def _save_model(self) -> None:
        self.db.save_app_model(self.eng_id, self.model.to_dict())

    # --- accounts ----------------------------------------------------------
    def add_account(self, account: Account) -> Account:
        a = self.model.add_account(account)
        self._save_model()
        self.log.record("human", "account %r registered (role=%s, auth=%s)"
                        % (a.label, a.role, a.auth_state))
        return a

    # --- the loop ----------------------------------------------------------
    def run(self, max_iterations: int = 200) -> Dict[str, Any]:
        """Drive the machine until a terminal state. Returns a run summary."""
        iterations = 0
        recon_summary: Dict[str, Any] = {}
        while not is_terminal(self.state) and iterations < max_iterations:
            iterations += 1
            if self.budget.exhausted():
                self._goto(ResearchState.BUDGET_EXHAUSTED, "research budget spent")
                break

            if self.state == ResearchState.SCOPE_VERIFIED:
                self._goto(ResearchState.RECON, "scope confirmed, starting observation")
            elif self.state == ResearchState.RECON:
                recon_summary = self._do_recon()
            elif self.state == ResearchState.APPLICATION_MODELING:
                self._do_modeling()
            elif self.state == ResearchState.HYPOTHESIS_GENERATED:
                self._do_prioritize()
            elif self.state == ResearchState.INVESTIGATION:
                self._do_investigation()
            elif self.state == ResearchState.VALIDATION:
                self._do_validation()
            elif self.state == ResearchState.BLOCKED_ON_RESEARCHER:
                if self.queue.open():
                    # a blocker was resolved (or new surface appeared): keep going
                    self._goto(ResearchState.HYPOTHESIS_GENERATED,
                               "%d hypothesis/es testable again" % len(self.queue.open()))
                else:
                    self._goto(ResearchState.HYPOTHESES_EXHAUSTED,
                               "all open hypotheses require researcher action")
        return self.summary(recon_summary, iterations)

    # --- OBSERVE -----------------------------------------------------------
    def _do_recon(self) -> Dict[str, Any]:
        orch = Orchestrator(self.db, self.eng_id, self.policy, self.graph,
                            store=self.store, fallback_prober=self.prober)
        summary = orch.run_recon(approvals=self.approvals,
                                 include_active_scan=self.include_active_scan,
                                 timeout=self.tool_timeout)
        self.graph = orch.graph
        self.db.save_graph(self.eng_id, self.graph.to_dict())
        self.budget.spend_tool_call(len(summary.get("ran", [])) + len(summary.get("failed", [])))

        records = summary.get("nuclei_records", [])
        hits = len(summary.get("nuclei_hits", []))
        # scanner output becomes model knowledge (info/low) or a hypothesis that
        # still has to be reproduced (medium+). It never becomes a finding directly.
        scanner_hyps = gain.from_scanner(records, self.model)
        if records:
            self._save_model()
        if scanner_hyps:
            self.queue.add_all(scanner_hyps)
            self.log.record("planner", "scanner hits queued as hypotheses",
                            result="%d of %d template matches were medium+ and need "
                                   "reproduction" % (len(scanner_hyps), len(records)),
                            state=self.state.value)
        elif records:
            self.log.record("modeler", "scanner hits recorded as context",
                            result="%d template matches, none above low severity; kept as "
                                   "notes on the endpoints, not as findings" % len(records),
                            state=self.state.value)
        for f in summary.get("failed", []) + summary.get("not_installed", []):
            self.log.record("recon", "tool failure diagnosed", result=f,
                            state=self.state.value)
        for r in summary.get("recovered", []):
            self.log.record("recon", "recovered via alternative path", result=r,
                            state=self.state.value)
        for miss in summary.get("not_installed", []):
            from .blockers import BlockerKind
            self.blockers.raise_blocker(
                BlockerKind.TOOL_MISSING, "install %s" % miss.split()[0],
                "the step %r could not run; the surface it would have found is a "
                "coverage gap, not an absence of bugs" % miss,
                how_to_provide="install the tool on PATH and re-run bbagent research")
        self.log.record("recon", "recon wave complete",
                        result="%d steps ran, %d records, %d nuclei hits, %d endpoints known"
                               % (len(summary.get("ran", [])), summary.get("records", 0),
                                  hits, len(self.graph.by_type("endpoint"))),
                        state=self.state.value)
        # THE point of this refactor: zero scanner hits means the shallow pass is
        # done, so go model the application.
        self._goto(ResearchState.APPLICATION_MODELING,
                   "scanners contributed %d hits; continuing into application modeling"
                   % hits)
        return summary

    # --- UNDERSTAND / MODEL ------------------------------------------------
    def _do_modeling(self) -> None:
        before = len(self.model.endpoints)
        self.model = from_graph(self.graph, self.model)
        self._save_model()
        step = gain.reason(self.model, None)
        self.log.record("modeler", "application model updated",
                        result="%d endpoints (+%d), %d object types, %d observed "
                               "authorization outcomes; missing: %s"
                               % (len(self.model.endpoints),
                                  len(self.model.endpoints) - before,
                                  len(self.model.resources), len(self.model.matrix),
                                  "; ".join(step.missing) or "nothing"),
                        state=self.state.value)
        if len(self.model.usable_accounts()) < 2:
            from .blockers import BlockerKind
            self.blockers.raise_blocker(
                BlockerKind.ACCOUNT_NEEDED,
                "a second researcher-controlled account",
                "cross-account authorization is the highest-value class left, and it "
                "cannot be tested with fewer than two identities",
                how_to_provide="bbagent account add B --role user "
                               "--token 'Authorization=env:BB_TOKEN_B'")
        self._goto(ResearchState.HYPOTHESIS_GENERATED, "model ready, generating hypotheses")

    # --- HYPOTHESIZE / PRIORITIZE -----------------------------------------
    def _do_prioritize(self) -> None:
        for h in self.queue.stuck():
            self.queue.update(replace(h, status=HypothesisStatus.REQUIRES_HUMAN_ACTION,
                                      learned=(h.learned + " | out of automated attempts "
                                               "after %d tries" % h.attempts).strip(" |")))
            self.log.record("planner", "parked after repeated failures", hypothesis_id=h.id,
                            result=h.observed, state=self.state.value)
        generated = gain.generate(self.model)
        if self.provider is not None:
            generated += self._llm_hypotheses()
        added = [h for h in generated
                 if self.db.get_hypothesis(self.eng_id, h.id) is None]
        self.queue.add_all(generated)
        self.log.record("planner", "hypotheses generated",
                        result="%d new, %d open in queue" % (len(added), len(self.queue.open())),
                        state=self.state.value)
        nxt = self.queue.next()
        if nxt is None:
            if self.blockers.open():
                self._goto(ResearchState.BLOCKED_ON_RESEARCHER,
                           "no testable hypothesis left; %d blocker(s) await the researcher"
                           % len(self.blockers.open()))
            else:
                self._goto(ResearchState.HYPOTHESES_EXHAUSTED,
                           "no hypothesis left worth testing against the current model")
            return
        self._goto(ResearchState.INVESTIGATION,
                   "next: %s (priority %.2f)" % (nxt.id, nxt.priority))

    def _llm_hypotheses(self) -> List[Hypothesis]:
        """Optional advisor. Its output is queued like any other hypothesis and is
        never trusted with authorization."""
        from ..agents import plan as plan_agent
        from .hypothesis import make_id
        try:
            lines = plan_agent.hypotheses(self.graph, self.provider)
        except Exception as e:                       # noqa: BLE001
            self.log.record("advisor", "LLM hypothesis generation failed", result=repr(e))
            return []
        out = []
        target = next(iter(self.model.endpoints.values())).url if self.model.endpoints else ""
        for line in lines[:8]:
            out.append(Hypothesis(
                id=make_id(Category.CONFIG, target or "model", line[:60]),
                category=Category.CONFIG, target=target, reasoning=line,
                expected_observation="(advisory; needs a concrete experiment)",
                authorization="B", priority=0.3))
        return out

    # --- INVESTIGATE / COMPARE --------------------------------------------
    def _do_investigation(self) -> None:
        h = self.queue.next()
        if h is None:
            self._goto(ResearchState.HYPOTHESIS_GENERATED, "queue drained mid-investigation")
            return
        step = gain.reason(self.model, h)
        self.log.record("investigator", "reasoning before acting", hypothesis_id=h.id,
                        authorization=step.authorization, result=step.render(),
                        state=self.state.value)

        self.queue.update(replace(h, status=HypothesisStatus.INVESTIGATING,
                                  attempts=h.attempts + 1))
        res = investigate(h, self.model, self.prober, approved=self.approve_investigation)
        self.budget.spend_investigation()
        self.budget.spend_tool_call(len(res.observations))
        self._save_model()

        if res.blocker is not None:
            b = self.blockers.raise_blocker(res.blocker.kind, res.blocker.what_is_needed,
                                            res.blocker.reasoning, hypothesis_id=h.id,
                                            how_to_provide=res.blocker.how_to_provide)
            self.log.record("investigator", "raised researcher blocker %s" % b.id,
                            hypothesis_id=h.id, result=b.what_is_needed,
                            state=self.state.value)

        updated = replace(h, status=res.status, observed=res.observed,
                          learned=res.learned or h.learned,
                          evidence=h.evidence + res.observations)
        self.queue.update(updated)
        self.log.record("investigator", "investigation result: %s" % res.status.value,
                        hypothesis_id=h.id, authorization=res.authorization,
                        result=res.observed, state=self.state.value)

        # LEARN: a rejection updates the model so the next hypothesis is better
        if res.learned:
            self.model.learn("GET %s" % h.target, res.learned)
            self._save_model()
            if res.status == HypothesisStatus.REJECTED:
                self.log.record("modeler", "model updated from a rejected hypothesis",
                                hypothesis_id=h.id, result=res.learned, state=self.state.value)

        if res.status == HypothesisStatus.SUPPORTED:
            self._goto(ResearchState.VALIDATION, "%s is supported; validating" % h.id)
        else:
            self._goto(ResearchState.HYPOTHESIS_GENERATED,
                       "%s -> %s; picking the next hypothesis" % (h.id, res.status.value))

    # --- VALIDATE ----------------------------------------------------------
    def _do_validation(self) -> None:
        supported = self.queue.by_status(HypothesisStatus.SUPPORTED)
        if not supported:
            self._goto(ResearchState.HYPOTHESIS_GENERATED, "nothing left to validate")
            return
        h = supported[0]
        # 1. reproducible?
        res2 = investigate(h, self.model, self.prober, approved=self.approve_investigation)
        self.budget.spend_investigation()
        reproduced = res2.status == HypothesisStatus.SUPPORTED
        # 2. security-relevant, or is there an expected-behavior explanation?
        benign = self._benign_explanation(h, res2)

        self.log.record("validator", "validation checks",
                        hypothesis_id=h.id,
                        result="reproducible=%s; benign explanation: %s"
                               % (reproduced, benign or "none found"),
                        state=self.state.value)

        if not reproduced:
            self.queue.update(replace(h, status=HypothesisStatus.REJECTED,
                                      learned="first observation did not reproduce (%s); "
                                              "treated as noise, not a finding" % res2.observed))
            self._goto(ResearchState.HYPOTHESIS_GENERATED, "%s did not reproduce" % h.id)
            return
        if benign:
            self.queue.update(replace(h, status=HypothesisStatus.REJECTED,
                                      learned="reproducible but explained by expected "
                                              "behavior: %s" % benign))
            self._goto(ResearchState.HYPOTHESIS_GENERATED,
                       "%s explained by expected behavior" % h.id)
            return

        finding = self._to_finding(h, res2)
        stored = self.db.add_finding(self.eng_id, finding)
        self.queue.update(replace(h, status=HypothesisStatus.VALIDATED,
                                  observed=res2.observed))
        self.log.record("validator", "finding recorded #%s" % stored["id"],
                        hypothesis_id=h.id, result=finding.title, state=self.state.value)
        self._goto(ResearchState.HYPOTHESIS_GENERATED, "validated %s" % h.id)

    def _benign_explanation(self, h: Hypothesis, res: Result) -> str:
        """Could this be expected behavior? Asked explicitly, before reporting.

        Conservative on purpose: a plausible benign reading blocks the finding.
        """
        d = res.diff or {}
        ep = self.model.endpoints.get("GET %s" % h.target)
        if ep is not None and ep.object_type in ("public", "static", "assets", "docs", "health"):
            return "endpoint operates on a resource type that is normally public (%s)" % ep.object_type
        if d and d.get("body_identical") and d.get("outcome_a") == d.get("outcome_b") == "authorized":
            if ep is None or not ep.object_id:
                return "identical response with no object id: likely a shared/public resource"
        if h.category == Category.AUTH and ep is not None and not ep.object_id:
            return "no object id in the path, so an anonymous 200 is not an authorization gap"
        return ""

    def _to_finding(self, h: Hypothesis, res: Result) -> Finding:
        ep = self.model.endpoints.get("GET %s" % h.target)
        obj = ep.object_type if ep else ""
        steps = "\n".join(
            "%d. %s %s as identity %r -> HTTP %s"
            % (i + 1, o.get("method"), o.get("url"), o.get("account"), o.get("status"))
            for i, o in enumerate(res.observations))
        # the two responses are often byte-identical (that is the point of an IDOR),
        # and the store is content-addressed, so list each object once
        evidence, seen_refs = [], set()
        for o in res.observations:
            ref = o.get("evidence_ref", "")
            if ref and ref not in seen_refs:
                seen_refs.add(ref)
                evidence.append({"kind": "http_response", "ref": ref,
                                 "sha256": o.get("sha256", "")})
        f = Finding(
            title="%s: %s" % (h.category.value.replace("_", " ").title(), h.target),
            asset=h.target, endpoint=h.target,
            vuln_class=h.category.value,
            preconditions="researcher-controlled accounts: %s"
                          % ", ".join(a.label for a in self.model.usable_accounts()),
            steps=steps,
            expected=h.expected_observation,
            actual=res.observed,
            impact="",                 # never invented; a human writes impact
            evidence=evidence,
        )
        if obj:
            f.preconditions += "; object type %s" % obj
        # reproduction already happened in _do_validation, so report it as such
        return validation.validate(
            f, self.policy,
            existing_fingerprints=self.db.existing_fingerprints(self.eng_id),
            reproduce_fn=lambda _f: (True, "independently re-requested during validation: %s"
                                     % res.observed))

    # --- reporting ---------------------------------------------------------
    def surface_counts(self) -> Dict[str, int]:
        return {
            "subdomains": len(self.graph.by_type("subdomain")),
            "urls": len(self.graph.by_type("url")),
            "endpoints_crawled": len(self.graph.by_type("endpoint")),
            "endpoints_modeled": len(self.model.endpoints),
            "object_types": len(self.model.resources),
            "accounts_usable": len(self.model.usable_accounts()),
        }

    def summary(self, recon_summary: Dict[str, Any], iterations: int) -> Dict[str, Any]:
        hs = self.queue.all()
        return {
            "state": self.state.value,
            "iterations": iterations,
            "recon": recon_summary,
            "hypotheses": self.queue.counts(),
            "blockers": [b.to_dict() for b in self.blockers.open()],
            "surface": self.surface_counts(),
            "budget": self.budget.to_dict(),
            "coverage": render_coverage(hs, self.budget, self.surface_counts()),
        }

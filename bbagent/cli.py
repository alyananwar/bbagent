"""bbagent CLI.

    bbagent program --brief scope.txt --url https://bugcrowd.com/acme
    bbagent scope
    bbagent confirm
    bbagent check https://api.acme.com/v1/users --class B
    bbagent findings
    bbagent report 3
    bbagent approve 3

State lives in a workspace dir (default ./.bbagent): a SQLite DB and an evidence
store. Target-directed actions run through the scope engine + policy gate.
"""
import argparse
import json
import os
import sys
from typing import Optional

from .models import ActionClass, FindingStatus
from . import intake, scope as scope_mod, policy as policy_mod
from .db import DB
from .evidence import EvidenceStore
from .graph import SurfaceGraph
from .orchestrator import Orchestrator


def _workspace(args) -> str:
    ws = args.workspace or os.path.join(os.getcwd(), ".bbagent")
    os.makedirs(ws, exist_ok=True)
    return ws


def _db(args) -> DB:
    return DB(os.path.join(_workspace(args), "bbagent.db"))


def _resolve_eng(db: DB, args) -> Optional[int]:
    if getattr(args, "engagement", None):
        return args.engagement
    return db.latest_engagement_id()


def _load_policy(db: DB, eng_id: int):
    row = db.get_engagement(eng_id)
    if not row:
        return None, None
    data = json.loads(row["data"])
    from .models import ScopePolicy, ScopeRule, RuleKind, ProgramPermissions
    pdata = data["policy"]
    pol = ScopePolicy(raw_source=pdata.get("raw_source", ""), source_url=pdata.get("source_url", ""))
    for r in pdata["in_scope"]:
        pol.in_scope.append(ScopeRule(kind=RuleKind(r["kind"]), value=r["value"], source=r.get("source", "")))
    for r in pdata["out_of_scope"]:
        pol.out_of_scope.append(ScopeRule(kind=RuleKind(r["kind"]), value=r["value"], source=r.get("source", "")))
    perms = pdata.get("permissions", {})
    pol.permissions = ProgramPermissions(**{k: perms[k] for k in perms if k in ProgramPermissions().__dict__})
    return row, pol


def _store(args) -> EvidenceStore:
    return EvidenceStore(os.path.join(_workspace(args), "evidence"))


def _graph_path(args, eng_id: int) -> str:
    return os.path.join(_workspace(args), "graph_%d.json" % eng_id)


def _load_graph(args, eng_id: int, db: DB) -> SurfaceGraph:
    """The DB owns the surface now. A graph_N.json from an older run is imported
    once so nothing discovered before this change is lost."""
    data = db.load_graph(eng_id)
    if data:
        return SurfaceGraph.from_dict(data)
    path = _graph_path(args, eng_id)
    if os.path.exists(path):
        with open(path) as f:
            graph = SurfaceGraph.from_dict(json.load(f))
        db.save_graph(eng_id, graph.to_dict())
        print("imported %d nodes from %s into the database" % (len(graph.nodes), path))
        return graph
    return SurfaceGraph()


def cmd_import(args) -> int:
    raw = None
    if args.brief:
        if not os.path.exists(args.brief):
            print("brief file not found: %s" % args.brief, file=sys.stderr)
            return 2
        with open(args.brief, "r", encoding="utf-8") as f:
            raw = f.read()
    eng, note = intake.import_program(args.url, raw_text=raw, allow_network=args.fetch,
                                      notes=args.name or "")
    print("note: %s" % note)
    if eng is None:
        print("could not build engagement automatically. Save the program brief to a "
              "file and run:\n  bbagent import %s --brief scope.txt" % args.url, file=sys.stderr)
        return 3
    db = _db(args)
    eng_id = db.add_engagement(eng)
    print("created engagement #%d  program=%r platform=%r status=%s"
          % (eng_id, eng.program, eng.platform, eng.status))
    print("parsed %d in-scope, %d out-of-scope rules. Review with `bbagent scope`, then `bbagent confirm`."
          % (len(eng.policy.in_scope), len(eng.policy.out_of_scope)))
    db.close()
    return 0


def cmd_recon(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    if row["status"] == "awaiting_scope_confirmation":
        print("scope not confirmed. run `bbagent confirm` first.", file=sys.stderr)
        return 3
    graph = _load_graph(args, eng_id, db)
    orch = Orchestrator(db, eng_id, pol, graph, store=_store(args))
    approvals = frozenset(args.approve or [])
    summary = orch.run_recon(approvals=approvals, include_active_scan=args.active,
                             timeout=args.tool_timeout)
    for key in ("ran", "recovered", "failed", "not_installed", "blocked",
                "needs_approval", "nuclei_hits"):
        items = summary.get(key, [])
        print("\n%s (%d):" % (key.upper(), len(items)))
        for it in items:
            print("  %s" % it)
    if summary.get("needs_approval"):
        print("\nTo run an approval-gated tool: bbagent recon --approve nuclei --active")
    print("\ngraph: %d nodes persisted to the database (engagement #%d)"
          % (len(orch.graph.nodes), eng_id))
    print("recon is only the observation phase. For the full research loop: bbagent research")
    db.close()
    return 0


def cmd_program(args) -> int:
    if not os.path.exists(args.brief):
        print("brief file not found: %s" % args.brief, file=sys.stderr)
        return 2
    with open(args.brief, "r", encoding="utf-8") as f:
        brief = f.read()
    eng = intake.from_brief(brief, program_url=args.url or "", program=args.name or "")
    db = _db(args)
    eng_id = db.add_engagement(eng)
    print("created engagement #%d  program=%r platform=%r status=%s"
          % (eng_id, eng.program, eng.platform, eng.status))
    print("parsed %d in-scope, %d out-of-scope rules. Review with `bbagent scope`, then `bbagent confirm`."
          % (len(eng.policy.in_scope), len(eng.policy.out_of_scope)))
    db.close()
    return 0


def cmd_scope(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement. run `bbagent program` first.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    print("engagement #%d  status=%s" % (eng_id, row["status"]))
    print("\nIN SCOPE:")
    for r in pol.in_scope:
        print("  + [%s] %s   (%s)" % (r.kind.value, r.value, r.source))
    print("\nOUT OF SCOPE:")
    for r in pol.out_of_scope:
        print("  - [%s] %s   (%s)" % (r.kind.value, r.value, r.source))
    print("\nPERMISSIONS:")
    for k, v in pol.permissions.to_dict().items():
        print("  %s = %s" % (k, v))
    db.close()
    return 0


def cmd_confirm(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row = db.get_engagement(eng_id)
    data = json.loads(row["data"])
    data["status"] = "scope_confirmed"
    db.conn.execute("UPDATE engagements SET status=?, data=? WHERE id=?",
                    ("scope_confirmed", json.dumps(data), eng_id))
    db.conn.commit()
    print("engagement #%d scope confirmed. target-directed actions now evaluated by the gate." % eng_id)
    db.close()
    return 0


def cmd_check(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    if row["status"] == "awaiting_scope_confirmation":
        print("scope not confirmed yet. run `bbagent confirm` after reviewing `bbagent scope`.", file=sys.stderr)
        return 3
    action_class = ActionClass(args.action_class)
    sd = scope_mod.evaluate(args.target, pol)
    verdict, reason = policy_mod.decide(action_class, sd.decision, pol)
    db.log_scope_decision(eng_id, sd.to_dict())
    print("target : %s" % args.target)
    print("class  : %s" % action_class.value)
    print("scope  : %s  (%s)" % (sd.decision.value, sd.reason))
    print("verdict: %s  (%s)" % (verdict.value.upper(), reason))
    db.close()
    return 0 if verdict.value != "deny" else 1


def cmd_findings(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    for f in db.list_findings(eng_id):
        d = json.loads(f["data"])
        print("#%d  [%s]  %s  (%s)  fp=%s"
              % (f["id"], f["status"], d.get("title", ""), d.get("vuln_class", ""), f["fingerprint"]))
    db.close()
    return 0


def cmd_report(args) -> int:
    from . import report
    from .models import Finding
    db = _db(args)
    row = db.get_finding(args.finding_id)
    if not row:
        print("finding #%d not found." % args.finding_id, file=sys.stderr)
        return 2
    d = json.loads(row["data"])
    d["status"] = FindingStatus(d.get("status", "draft"))
    finding = Finding(**{k: d[k] for k in d if k in Finding.__dataclass_fields__})
    try:
        print(report.render(finding, strict=not args.draft))
    except report.IncompleteFinding as e:
        print(str(e), file=sys.stderr)
        print("(re-run with --draft to render anyway with gaps marked)", file=sys.stderr)
        return 3
    db.close()
    return 0


def cmd_approve(args) -> int:
    db = _db(args)
    ok = db.set_finding_status(args.finding_id, FindingStatus.FINALIZED)
    if ok:
        print("finding #%d finalized (immutable). Submission remains a manual, human step." % args.finding_id)
    else:
        print("could not finalize #%d (not found or already finalized)." % args.finding_id, file=sys.stderr)
    db.close()
    return 0 if ok else 2


def _loop(args, db: DB, eng_id: int, pol):
    from .research.coverage import Budget
    from .research.loop import ResearchLoop
    budget = Budget(max_tool_calls=args.max_tool_calls, max_seconds=args.max_seconds,
                    max_investigations=args.max_investigations)
    _load_graph(args, eng_id, db)          # migrate a legacy graph file if present
    return ResearchLoop(db, eng_id, pol, store=_store(args), budget=budget,
                        approvals=frozenset(args.approve or []),
                        approve_investigation=args.approve_investigation,
                        include_active_scan=args.active,
                        tool_timeout=args.tool_timeout)


def cmd_research(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    if row["status"] == "awaiting_scope_confirmation":
        print("scope not confirmed. run `bbagent confirm` first.", file=sys.stderr)
        return 3
    loop = _loop(args, db, eng_id, pol)
    summary = loop.run(max_iterations=args.max_iterations)

    print("\nFINAL STATE: %s   (%d loop iterations)" % (summary["state"], summary["iterations"]))
    print("\nHYPOTHESES: " + ", ".join("%s=%d" % (k, v) for k, v in summary["hypotheses"].items() if v))
    print("\n" + summary["coverage"])
    if summary["blockers"]:
        print("\nRESEARCHER ACTION REQUIRED (%d):" % len(summary["blockers"]))
        for b in summary["blockers"]:
            print("  [%s] %s\n      why: %s\n      how: %s"
                  % (b["id"], b["what_is_needed"], b["reasoning"], b["how_to_provide"]))
        print("\n  Resolve one, then re-run `bbagent research` -- the loop resumes where it parked.")
    print("\nfindings: bbagent findings   |   log: bbagent researchlog   |   "
          "hypotheses: bbagent hypotheses")
    db.close()
    return 0


def cmd_hypotheses(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    from .research.hypothesis import HypothesisQueue
    q = HypothesisQueue(db, eng_id)
    rows = q.all()
    if not rows:
        print("no hypotheses yet. run `bbagent research`.")
        return 0
    for h in sorted(rows, key=lambda x: (x.status.value, -x.priority)):
        print("%-22s %-10s p=%.2f  %-14s %s" % (h.id, h.status.value, h.priority,
                                                h.category.value, h.target))
        print("     reasoning: %s" % h.reasoning)
        print("     expected : %s" % h.expected_observation)
        if h.observed:
            print("     observed : %s" % h.observed)
        if h.learned:
            print("     learned  : %s" % h.learned)
    db.close()
    return 0


def cmd_blockers(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    from .research.blockers import BlockerQueue
    for b in BlockerQueue(db, eng_id).all():
        print("%s %-22s %s" % ("[open]  " if not b.resolved else "[closed]", b.id, b.what_is_needed))
        print("     why: %s" % b.reasoning)
        if b.how_to_provide:
            print("     how: %s" % b.how_to_provide)
        if b.resolved:
            print("     resolution: %s" % b.resolution)
    db.close()
    return 0


def cmd_resolve(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    from .research.blockers import BlockerQueue
    from .research.hypothesis import HypothesisQueue, HypothesisStatus, replace
    ident = args.id
    bq = BlockerQueue(db, eng_id)
    b = bq.resolve(ident, args.note or "provided by researcher")
    hq = HypothesisQueue(db, eng_id)
    reopened = []
    targets = [h for h in hq.all()
               if h.status == HypothesisStatus.REQUIRES_HUMAN_ACTION
               and (h.id == ident or (b is not None and h.id == b.hypothesis_id))]
    for h in targets:
        hq.update(replace(h, status=HypothesisStatus.UNTESTED,
                          learned=(h.learned + " | researcher input: " + (args.note or "")).strip(" |")))
        reopened.append(h.id)
    if b is None and not reopened:
        print("no blocker or hypothesis with id %r." % ident, file=sys.stderr)
        return 2
    if b is not None:
        print("blocker %s closed." % b.id)
    for hid in reopened:
        print("hypothesis %s back in the queue as untested." % hid)
    if reopened:
        from .research.state import ResearchState
        db.set_research_state(eng_id, ResearchState.HYPOTHESIS_GENERATED.value,
                              {"reason": "researcher resolved %s" % ident})
    print("re-run `bbagent research` to continue from here.")
    db.close()
    return 0


def cmd_account(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    from .research.appmodel import Account, AppModel, UnsafeTokenRef
    data = db.load_app_model(eng_id)
    model = AppModel.from_dict(data) if data else AppModel()
    try:
        acct = Account(label=args.label, role=args.role, token_ref=args.token or "",
                       identity=args.identity or "",
                       auth_state="credentials_provided" if args.token else "none",
                       owns=args.owns or [])
    except UnsafeTokenRef as e:
        print("refusing to store that token: %s" % e, file=sys.stderr)
        print("  export BB_TOKEN_%s='<the secret>'\n"
              "  bbagent account %s --role %s --token 'Authorization=env:BB_TOKEN_%s'"
              % (args.label, args.label, args.role, args.label), file=sys.stderr)
        db.close()
        return 4
    model.add_account(acct)
    db.save_app_model(eng_id, model.to_dict())
    print("account %r registered: role=%s auth_state=%s token_ref=%s"
          % (acct.label, acct.role, acct.auth_state, acct.token_ref or "(none)"))
    if args.token and "=env:" in args.token:
        var = args.token.split("=env:", 1)[1]
        print("the secret itself stays in $%s and is never written to the workspace." % var)
        if not os.environ.get(var):
            print("warning: $%s is not set in this shell yet." % var, file=sys.stderr)
    db.close()
    return 0


def cmd_browser(args) -> int:
    """Import a browser network capture and fold it into the application model."""
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    if row["status"] == "awaiting_scope_confirmation":
        print("scope not confirmed. run `bbagent confirm` first.", file=sys.stderr)
        return 3
    if not os.path.exists(args.capture):
        print("capture file not found: %s" % args.capture, file=sys.stderr)
        return 2
    with open(args.capture, "r", encoding="utf-8") as f:
        raw = f.read()

    from .research import browser
    from .research.appmodel import AppModel
    from .research.hypothesis import HypothesisQueue
    from .research.log import ResearchLog
    from . import scope as scope_mod
    from .research import gain

    try:
        requests = (browser.from_har(raw, args.workflow or "")
                    if '"log"' in raw[:400] else
                    browser.from_records(json.loads(raw), args.workflow or ""))
    except ValueError as e:
        print("could not parse capture (expected HAR or a JSON list): %s" % e, file=sys.stderr)
        return 3

    # the gate applies to captured traffic too: anything out of scope is dropped
    # rather than modeled, so a stray tab cannot widen the engagement
    kept, dropped = [], []
    for r in requests:
        decision = scope_mod.evaluate(r.url, pol).decision.value
        (kept if decision == "in_scope" else dropped).append(r)

    data = db.load_app_model(eng_id)
    model = AppModel.from_dict(data) if data else AppModel()
    browser.fold(model, kept)
    db.save_app_model(eng_id, model.to_dict())

    queue = HypothesisQueue(db, eng_id)
    new = [h for h in gain.from_browser(kept, model)
           if db.get_hypothesis(eng_id, h.id) is None]
    queue.add_all(gain.from_browser(kept, model))

    summary = browser.workflow_summary(kept)
    ResearchLog(db, eng_id).record(
        "browser", "imported network capture %s" % os.path.basename(args.capture),
        result="%d in-scope requests kept, %d out-of-scope dropped, %d endpoints modeled, "
               "%d new hypotheses" % (len(kept), len(dropped), len(model.endpoints), len(new)))

    print("captured requests : %d  (kept %d in scope, dropped %d out of scope)"
          % (len(requests), len(kept), len(dropped)))
    print("workflows         : %s" % summary["workflows"])
    print("methods           : %s" % summary["methods"])
    print("auth kinds        : %s   (values never stored)" % summary["auth_kinds"])
    print("object types      : %s" % ", ".join(summary["object_types"]) or "none")
    print("endpoints modeled : %d" % len(model.endpoints))
    print("new hypotheses    : %d" % len(new))
    if dropped:
        hosts = sorted({__import__("urllib.parse", fromlist=["urlparse"]).urlparse(r.url).hostname
                        or "?" for r in dropped})
        print("dropped hosts     : %s" % ", ".join(hosts))
    db.close()
    return 0


def cmd_coverage(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    from .research.coverage import render
    from .research.hypothesis import HypothesisQueue
    from .research.loop import ResearchLoop
    loop = ResearchLoop(db, eng_id, pol, store=_store(args))
    print(render(HypothesisQueue(db, eng_id).all(), None, loop.surface_counts()))
    print("\nstate: %s" % loop.state.value)
    db.close()
    return 0


def cmd_researchlog(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    from .research.log import ResearchLog
    out = ResearchLog(db, eng_id).render(limit=args.limit)
    print(out or "research log is empty. run `bbagent research`.")
    db.close()
    return 0


def cmd_model(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    from .research.appmodel import AppModel
    data = db.load_app_model(eng_id)
    if not data:
        print("no application model yet. run `bbagent research`.")
        return 0
    m = AppModel.from_dict(data)
    print("ACCOUNTS:")
    for a in m.accounts.values():
        print("  %-10s role=%-10s auth=%-22s %s" % (a.label, a.role, a.auth_state,
                                                    a.token_ref or ""))
    print("\nOBJECT TYPES:")
    for r in m.resources.values():
        print("  %-16s owner_scoped=%s ids=%s" % (r.name, r.owner_scoped, r.observed_ids[:5]))
    print("\nENDPOINTS (%d):" % len(m.endpoints))
    for ep in list(m.endpoints.values())[:args.limit]:
        print("  %-42s object=%-12s id=%-8s role=%-10s state_changing=%s"
              % (ep.key[:42], ep.object_type, ep.object_id, ep.requires_role, ep.changes_state))
        for note in ep.notes:
            print("      learned: %s" % note)
    print("\nAUTHORIZATION MATRIX (%d observed):" % len(m.matrix))
    for k, v in list(m.matrix.items())[:args.limit]:
        role, key = k.split("|", 1)
        print("  %-10s %-46s %s" % (role, key[:46], v))
    db.close()
    return 0


def cmd_researchreport(args) -> int:
    db = _db(args)
    eng_id = _resolve_eng(db, args)
    if not eng_id:
        print("no engagement.", file=sys.stderr)
        return 2
    row, pol = _load_policy(db, eng_id)
    from .research import report as research_report
    from .research.blockers import BlockerQueue
    from .research.hypothesis import HypothesisQueue
    from .research.log import ResearchLog
    from .research.loop import ResearchLoop
    loop = ResearchLoop(db, eng_id, pol, store=_store(args))
    findings = [json.loads(f["data"]) for f in db.list_findings(eng_id)]
    text = research_report.render(
        program=json.loads(row["data"]).get("program", ""),
        state=loop.state.value,
        hypotheses=HypothesisQueue(db, eng_id).all(),
        findings=findings,
        blockers=BlockerQueue(db, eng_id).open(),
        surface=loop.surface_counts(),
        log_tail=ResearchLog(db, eng_id).render(limit=args.log_lines))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote %s" % args.out)
    else:
        print(text)
    db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bbagent", description="authorized bug bounty research core")
    p.add_argument("--workspace", help="state directory (default ./.bbagent)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("program", help="create engagement from a scope brief")
    sp.add_argument("--brief", required=True, help="path to program brief text file")
    sp.add_argument("--url", help="program URL")
    sp.add_argument("--name", help="program name")
    sp.set_defaults(func=cmd_program)

    sp = sub.add_parser("import", help="import a program from a URL (link -> engagement)")
    sp.add_argument("url", help="bug bounty program URL")
    sp.add_argument("--brief", help="path to a saved brief (reliable; use when fetch can't)")
    sp.add_argument("--fetch", action="store_true", help="attempt best-effort network fetch (check ToS)")
    sp.add_argument("--name", help="notes / program name")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("recon", help="run gated recon and build the attack surface")
    sp.add_argument("--engagement", type=int)
    sp.add_argument("--approve", action="append", help="approve an action-gated tool, e.g. --approve nuclei")
    sp.add_argument("--active", action="store_true", help="include active security scanning steps (still gated)")
    sp.add_argument("--tool-timeout", type=int, default=300, help="per-tool timeout in seconds")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("research", help="run the full research loop (recon -> model -> "
                                         "hypothesize -> investigate -> validate)")
    sp.add_argument("--engagement", type=int)
    sp.add_argument("--approve", action="append", help="approve a gated recon tool, e.g. nuclei")
    sp.add_argument("--active", action="store_true", help="include active scanning steps")
    sp.add_argument("--approve-investigation", action="store_true",
                    help="approve approval-gated investigations (incl. state-changing tests)")
    sp.add_argument("--max-tool-calls", type=int, default=200)
    sp.add_argument("--max-investigations", type=int, default=100)
    sp.add_argument("--max-seconds", type=int, default=1800)
    sp.add_argument("--max-iterations", type=int, default=200)
    sp.add_argument("--tool-timeout", type=int, default=300, help="per-tool timeout in seconds")
    sp.set_defaults(func=cmd_research)

    sp = sub.add_parser("hypotheses", help="list hypotheses and what each one taught us")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_hypotheses)

    sp = sub.add_parser("blockers", help="list researcher-action blockers")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_blockers)

    sp = sub.add_parser("resolve", help="close a blocker (or reopen a parked hypothesis) by id")
    sp.add_argument("id", help="blocker id or hypothesis id")
    sp.add_argument("--note", help="what you provided / what you observed")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_resolve)

    sp = sub.add_parser("account", help="register a researcher-controlled test account")
    sp.add_argument("label", help="short label, e.g. A or B")
    sp.add_argument("--role", default="user")
    sp.add_argument("--token", help="auth material reference, e.g. 'Authorization=env:BB_TOKEN_B'")
    sp.add_argument("--identity", help="the user id/email this account is")
    sp.add_argument("--owns", action="append", help="object id this account legitimately owns")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_account)

    sp = sub.add_parser("browser", help="import a browser network capture (HAR or JSON) "
                                       "and correlate UI actions with API endpoints")
    sp.add_argument("capture", help="path to a .har export or a JSON list of requests")
    sp.add_argument("--workflow", help="label for the UI action you performed, "
                                       "e.g. 'create feature flag'")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_browser)

    sp = sub.add_parser("coverage", help="research coverage bars and budget")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_coverage)

    sp = sub.add_parser("researchlog", help="chronological decision log")
    sp.add_argument("--limit", type=int)
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_researchlog)

    sp = sub.add_parser("researchreport", help="full engagement report: coverage, "
                                              "hypotheses tested and rejected, validated evidence")
    sp.add_argument("--out", help="write markdown to this file instead of stdout")
    sp.add_argument("--log-lines", type=int, default=25)
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_researchreport)

    sp = sub.add_parser("model", help="show the application model (roles, objects, matrix)")
    sp.add_argument("--limit", type=int, default=40)
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_model)

    sp = sub.add_parser("scope", help="show parsed scope for an engagement")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_scope)

    sp = sub.add_parser("confirm", help="confirm scope (required before target-directed actions)")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_confirm)

    sp = sub.add_parser("check", help="evaluate a target through scope + policy gate")
    sp.add_argument("target")
    sp.add_argument("--class", dest="action_class", default="B",
                    choices=[c.value for c in ActionClass], help="action class A-E (default B)")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("findings", help="list findings")
    sp.add_argument("--engagement", type=int)
    sp.set_defaults(func=cmd_findings)

    sp = sub.add_parser("report", help="render a submission-ready report")
    sp.add_argument("finding_id", type=int)
    sp.add_argument("--draft", action="store_true", help="render even if fields are missing")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("approve", help="finalize a finding (human gate; not submission)")
    sp.add_argument("finding_id", type=int)
    sp.set_defaults(func=cmd_approve)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

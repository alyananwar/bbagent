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


def _graph_path(args, eng_id: int) -> str:
    return os.path.join(_workspace(args), "graph_%d.json" % eng_id)


def _load_graph(args, eng_id: int) -> SurfaceGraph:
    path = _graph_path(args, eng_id)
    if os.path.exists(path):
        with open(path) as f:
            return SurfaceGraph.from_dict(json.load(f))
    return SurfaceGraph()


def _save_graph(args, eng_id: int, graph: SurfaceGraph) -> None:
    with open(_graph_path(args, eng_id), "w") as f:
        json.dump(graph.to_dict(), f, indent=2)


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
    graph = _load_graph(args, eng_id)
    orch = Orchestrator(db, eng_id, pol, graph)
    approvals = frozenset(args.approve or [])
    summary = orch.run_recon(approvals=approvals, include_active_scan=args.active)
    _save_graph(args, eng_id, orch.graph)
    for key in ("ran", "not_installed", "blocked", "needs_approval", "nuclei_hits"):
        items = summary.get(key, [])
        print("\n%s (%d):" % (key.upper(), len(items)))
        for it in items:
            print("  %s" % it)
    if summary.get("needs_approval"):
        print("\nTo run an approval-gated tool: bbagent recon --approve nuclei --active")
    print("\ngraph: %d nodes saved to %s" % (len(orch.graph.nodes), _graph_path(args, eng_id)))
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
    sp.set_defaults(func=cmd_recon)

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

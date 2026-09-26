"""Scope-gated external tool runner.

This does NOT contain any attack payloads or built-in exploits. It is a wrapper
that runs whatever external security tool YOU have installed (subfinder, httpx,
nuclei, nmap, ...) and ONLY after the target passes the deterministic scope
engine and the policy gate. Every run is recorded with full provenance.

The gate is the whole point: a tool never touches a target the scope engine has
not authorized for the tool's action class.
"""
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .models import ActionClass, ScopePolicy, ToolRun, Verdict
from . import scope, policy


class ScopeViolation(Exception):
    pass


class ApprovalRequired(Exception):
    def __init__(self, verdict_reason: str):
        super().__init__(verdict_reason)
        self.reason = verdict_reason


def _tool_version(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        return "not-installed"
    for flag in ("-version", "--version", "-V"):
        try:
            out = subprocess.run([tool, flag], capture_output=True, text=True, timeout=10)
            text = (out.stdout or out.stderr).strip().splitlines()
            if text:
                return text[0][:120]
        except Exception:
            continue
    return "unknown"


def gate(target: str, action_class: ActionClass, policy_obj: ScopePolicy):
    """Return (verdict, scope_decision, reason). Pure decision, no side effects."""
    sd = scope.evaluate(target, policy_obj)
    verdict, reason = policy.decide(action_class, sd.decision, policy_obj)
    return verdict, sd, reason


def run(tool: str,
        args: List[str],
        target: str,
        action_class: ActionClass,
        policy_obj: ScopePolicy,
        approved: bool = False,
        timeout: int = 300) -> ToolRun:
    """Run an external tool against a target, gated by scope + policy.

    - Verdict DENY  -> ScopeViolation, tool never executes.
    - Verdict REQUIRE_APPROVAL and not approved -> ApprovalRequired.
    - Verdict ALLOW (or approved) -> execute and record.
    """
    verdict, sd, reason = gate(target, action_class, policy_obj)

    run_rec = ToolRun(
        tool=tool, version=_tool_version(tool), args=list(args), target=target,
        scope_decision=sd.to_dict(), verdict=verdict.value,
    )

    if verdict == Verdict.DENY:
        raise ScopeViolation("%s blocked for %s: %s" % (tool, target, reason))
    if verdict == Verdict.REQUIRE_APPROVAL and not approved:
        raise ApprovalRequired(reason)

    if shutil.which(tool) is None:
        run_rec.exit_code = None
        run_rec.stderr_ref = "tool not installed on PATH"
        run_rec.finished_at = datetime.now(timezone.utc).isoformat()
        return run_rec

    try:
        proc = subprocess.run([tool, *args], capture_output=True, text=True, timeout=timeout)
        run_rec.exit_code = proc.returncode
        run_rec.stdout_ref = proc.stdout[-8000:]
        run_rec.stderr_ref = proc.stderr[-2000:]
    except subprocess.TimeoutExpired:
        run_rec.exit_code = None
        run_rec.stderr_ref = "timeout after %ss" % timeout
    run_rec.finished_at = datetime.now(timezone.utc).isoformat()
    return run_rec

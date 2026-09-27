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


NOT_INSTALLED = "tool not installed on PATH"


def _version_text(tool: str) -> str:
    """Full version/banner output, used for both the version string and the
    identity check. Returns "" when nothing could be read."""
    if not shutil.which(tool):
        return ""
    for flag in ("-version", "--version", "-V"):
        try:
            out = subprocess.run([tool, flag], capture_output=True, text=True, timeout=10)
            text = ((out.stdout or "") + "\n" + (out.stderr or "")).strip()
            if text:
                return text[:2000]
        except Exception:
            continue
    return ""


def _tool_version(tool: str) -> str:
    text = _version_text(tool)
    if not text:
        return "not-installed" if not shutil.which(tool) else "unknown"
    for line in text.splitlines():
        line = line.strip()
        if line and "projectdiscovery.io" not in line and not line.startswith(("_", "/", "\\", "|")):
            return line[:120]
    return text.splitlines()[0][:120]


def wrong_binary(tool: str, identity_hint: str) -> Optional[str]:
    """Confirm the binary on PATH is the tool we think it is.

    Real case this catches: `httpx` on PATH being the Python HTTP client instead
    of projectdiscovery's httpx. Both exit 0, one produces useless output, and the
    run looks successful while the pipeline silently starves downstream steps.
    Returns a diagnosis string on mismatch, None when it looks right.
    """
    if not identity_hint or not shutil.which(tool):
        return None
    text = _version_text(tool).lower()
    if not text:
        return None
    for hint in [h.strip().lower() for h in identity_hint.split("|") if h.strip()]:
        if hint in text:
            return None
    return ("%s on PATH (%s) does not look like the expected tool: version output "
            "has none of %r. Fix PATH or pass the right binary."
            % (tool, shutil.which(tool), identity_hint))


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
        timeout: int = 300,
        store=None,
        identity_hint: str = "") -> ToolRun:
    """Run an external tool against a target, gated by scope + policy.

    - Verdict DENY  -> ScopeViolation, tool never executes.
    - Verdict REQUIRE_APPROVAL and not approved -> ApprovalRequired.
    - Verdict ALLOW (or approved) -> execute and record.

    store: an EvidenceStore. When given, the FULL stdout is written to it
    content-addressed and stdout_ref points at that object. Output is never
    truncated before the parser sees it (run.stdout always holds all of it):
    truncating here was silently dropping most crawled endpoints.
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
        run_rec.stderr_ref = NOT_INSTALLED
        run_rec.finished_at = datetime.now(timezone.utc).isoformat()
        return run_rec

    mismatch = wrong_binary(tool, identity_hint)
    if mismatch:
        run_rec.exit_code = None
        run_rec.stderr_ref = mismatch
        run_rec.finished_at = datetime.now(timezone.utc).isoformat()
        return run_rec

    try:
        proc = subprocess.run([tool, *args], capture_output=True, text=True, timeout=timeout)
        run_rec.exit_code = proc.returncode
        run_rec.stdout = proc.stdout or ""
        run_rec.stderr_ref = (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired as e:
        run_rec.exit_code = None
        # keep whatever the tool emitted before the timeout instead of discarding it
        partial = e.stdout or ""
        run_rec.stdout = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
        run_rec.stderr_ref = "timeout after %ss (kept %d bytes of partial output)" % (
            timeout, len(run_rec.stdout))

    run_rec.stdout_bytes = len(run_rec.stdout)
    if run_rec.stdout:
        if store is not None:
            ev = store.add("tool_output", run_rec.stdout)
            run_rec.stdout_ref = ev.ref
            run_rec.stdout_sha256 = ev.sha256
        else:
            # no store: keep a bounded preview in the record, but run.stdout above
            # still carries everything for the parser in this process
            run_rec.stdout_ref = run_rec.stdout[:8000]
    run_rec.finished_at = datetime.now(timezone.utc).isoformat()
    return run_rec

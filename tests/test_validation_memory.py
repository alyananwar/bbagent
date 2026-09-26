import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import Finding, FindingStatus, RuleKind, ScopePolicy, ScopeRule
from bbagent import validation
from bbagent.memory import Memory


def _pol():
    return ScopePolicy(in_scope=[ScopeRule(RuleKind.WILDCARD_DOMAIN, "*.acme.com")])


def _finding():
    return Finding(title="XSS", asset="a.acme.com", endpoint="https://a.acme.com/s?q=1",
                   vuln_class="xss", severity="high")


def test_out_of_scope_rejected():
    f = Finding(title="x", asset="evil.com", endpoint="https://evil.com/x", vuln_class="xss")
    out = validation.validate(f, _pol())
    assert out.status == FindingStatus.REJECTED


def test_no_repro_stays_draft_capped():
    out = validation.validate(_finding(), _pol())
    assert out.status == FindingStatus.DRAFT
    assert out.confidence <= 0.5


def test_reproduced_becomes_validated():
    out = validation.validate(_finding(), _pol(), reproduce_fn=lambda f: (True, "200 with payload reflected"))
    assert out.status == FindingStatus.VALIDATED
    assert out.confidence > 0.5


def test_failed_repro_rejected():
    out = validation.validate(_finding(), _pol(), reproduce_fn=lambda f: (False, "not reflected"))
    assert out.status == FindingStatus.REJECTED


def test_duplicate_detected():
    fp = validation.dedup.fingerprint(_finding())
    out = validation.validate(_finding(), _pol(), existing_fingerprints=[fp])
    assert out.status == FindingStatus.DUPLICATE


def test_input_not_mutated():
    f = _finding()
    validation.validate(f, _pol(), reproduce_fn=lambda x: (True, "ok"))
    assert f.status == FindingStatus.DRAFT   # original untouched


def test_memory_scope_override():
    with tempfile.TemporaryDirectory() as d:
        m = Memory(os.path.join(d, "m.db"))
        m.set("global", "", "rps", 10)
        m.set("program", "acme", "rps", 3)
        assert m.merged("rps", program="acme") == 3
        assert m.merged("rps") == 10
        m.close()


def test_memory_false_positives():
    with tempfile.TemporaryDirectory() as d:
        m = Memory(os.path.join(d, "m.db"))
        m.record_false_positive("acme", "abc123")
        assert "abc123" in m.false_positives("acme")
        m.close()


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

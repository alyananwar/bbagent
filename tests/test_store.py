import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.models import Finding, FindingStatus
from bbagent import dedup
from bbagent.db import DB
from bbagent.evidence import EvidenceStore


def test_fingerprint_stable_across_ids():
    f1 = Finding(title="IDOR", asset="api.acme.com", endpoint="/v1/users/1", vuln_class="idor")
    f2 = Finding(title="IDOR", asset="api.acme.com", endpoint="/v1/users/2", vuln_class="idor")
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


def test_fingerprint_differs_by_class():
    f1 = Finding(title="x", asset="api.acme.com", endpoint="/v1/users/1", vuln_class="idor")
    f2 = Finding(title="x", asset="api.acme.com", endpoint="/v1/users/1", vuln_class="xss")
    assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


def test_db_dedup_marks_duplicate():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng_id = db.add_engagement(__import__("bbagent.models", fromlist=["Engagement"]).Engagement(program="acme"))
        r1 = db.add_finding(eng_id, Finding(title="IDOR", asset="api.acme.com", endpoint="/v1/users/1", vuln_class="idor"))
        r2 = db.add_finding(eng_id, Finding(title="IDOR", asset="api.acme.com", endpoint="/v1/users/2", vuln_class="idor"))
        assert r1["status"] == "draft"
        assert r2["status"] == "duplicate"
        db.close()


def test_finalized_is_immutable():
    with tempfile.TemporaryDirectory() as d:
        db = DB(os.path.join(d, "t.db"))
        eng_id = db.add_engagement(__import__("bbagent.models", fromlist=["Engagement"]).Engagement(program="acme"))
        r = db.add_finding(eng_id, Finding(title="X", asset="a.com", endpoint="/x", vuln_class="xss"))
        assert db.set_finding_status(r["id"], FindingStatus.FINALIZED) is True
        # cannot move finalized back to draft
        assert db.set_finding_status(r["id"], FindingStatus.DRAFT) is False
        # but can mark submitted
        assert db.set_finding_status(r["id"], FindingStatus.SUBMITTED) is True
        db.close()


def test_evidence_content_addressed_and_verifies():
    with tempfile.TemporaryDirectory() as d:
        store = EvidenceStore(d)
        e1 = store.add("log", "same bytes")
        e2 = store.add("log", "same bytes")
        assert e1.sha256 == e2.sha256          # dedup by content
        assert store.verify(e1) is True
        assert store.read(e1) == b"same bytes"


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

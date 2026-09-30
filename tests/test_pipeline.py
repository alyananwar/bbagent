"""Scout, the Storyteller checkpoint, and the Submitter compliance gate."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent import scout, submit
from bbagent.agents import report_writer
from bbagent.llm.fake import FakeProvider
from bbagent.models import Finding, FindingStatus
from bbagent.program_intel import parse_brief

RICH = """Acme Bounty
Rewards range from $500 to $20,000 per valid report.
Active testing is allowed. Automated scanning is allowed. Proof of concept is permitted.

In scope:
- *.acme.com
- api.acme.com
- https://app.acme.com

Out of scope:
- blog.acme.com
"""

POOR = """Tiny Bounty
Swag only, up to $100.
No automated scanning. 2 requests per second.
Denial of service reports are ineligible.

In scope:
- one.tiny.com

Out of scope:
- two.tiny.com
- three.tiny.com
- four.tiny.com
"""


def _finalized_finding(**over):
    base = dict(
        title="Cross-account read on order endpoint",
        asset="api.acme.com",
        endpoint="https://api.acme.com/v2/orders/1042",
        vuln_class="idor",
        steps="1. auth as A\n2. GET /v2/orders/1042 (owned by B)",
        expected="403",
        actual="200 with B's order body",
        evidence=[{"kind": "http", "ref": "obs/1", "sha256": "ab" * 32}],
        status=FindingStatus.FINALIZED,
    )
    base.update(over)
    return Finding(**base)


# --- Scout -----------------------------------------------------------------

def test_scout_parses_reward_forms():
    assert scout.parse_max_reward("up to $20,000 per report") == 20000
    assert scout.parse_max_reward("pays $5k max") == 5000
    assert scout.parse_max_reward("no money here") is None
    # largest figure wins, not the first
    assert scout.parse_max_reward("$500 to $20,000") == 20000


def test_scout_wildcard_counts_for_more_surface():
    wide = scout.evaluate("wide", RICH)
    narrow = scout.evaluate("narrow", POOR)
    assert wide.surface > narrow.surface
    # *.acme.com alone is weighted above a single host
    assert wide.surface >= 3.0


def test_scout_friction_rises_with_restrictions():
    rich = scout.evaluate("rich", RICH)
    poor = scout.evaluate("poor", POOR)
    assert poor.friction > rich.friction
    joined = " ".join(poor.reasons)
    assert "automated scanning not allowed" in joined
    assert "req/sec" in joined


def test_scout_ranks_rich_program_first_and_explains():
    ranked = scout.rank([scout.evaluate("poor", POOR), scout.evaluate("rich", RICH)])
    assert [c.name for c in ranked] == ["rich", "poor"]
    text = scout.render(ranked)
    assert "Recommendation: rich." in text
    assert "Why:" in text
    # honesty about what it is NOT
    assert "no researcher API lists programs" in text


def test_scout_flags_ineligible_report_types():
    poor = scout.evaluate("poor", POOR)
    assert any("denial of service" in h for h in poor.ineligible_hints)


def test_scout_loads_a_directory_and_is_stable():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "rich.txt"), "w").write(RICH)
        open(os.path.join(d, "poor.md"), "w").write(POOR)
        open(os.path.join(d, "ignore.pdf"), "w").write("not a brief")
        first = [c.name for c in scout.load_dir(d)]
        assert first == ["rich", "poor"]
        assert first == [c.name for c in scout.load_dir(d)]


def test_scout_empty_dir_says_what_to_do():
    with tempfile.TemporaryDirectory() as d:
        assert "No briefs found" in scout.render(scout.load_dir(d))


# --- Storyteller checkpoint -------------------------------------------------

def test_storyteller_refuses_before_human_certifies():
    draft = _finalized_finding(status=FindingStatus.VALIDATED)
    try:
        report_writer.narrate(draft, FakeProvider(default="prose"))
    except report_writer.NotCertified as exc:
        assert "approve" in str(exc)
    else:
        raise AssertionError("narrate must refuse an uncertified finding")


def test_storyteller_runs_once_certified():
    fake = FakeProvider(default="# Cross-account read\n\nPlain prose.\n")
    out = report_writer.narrate(_finalized_finding(), fake)
    assert "Plain prose" in out
    assert fake.calls[0]["tier"] == "strong"


def test_storyteller_prompt_forbids_new_facts():
    fake = FakeProvider(default="ok")
    report_writer.narrate(_finalized_finding(), fake)
    system = fake.calls[0]["system"]
    assert "no new facts" in system.lower()
    assert "a human writes impact" in system


def test_storyteller_falls_back_to_deterministic_on_empty_model_output():
    out = report_writer.narrate(_finalized_finding(), FakeProvider(default="   "))
    assert "Steps to Reproduce" in out


# --- Submitter --------------------------------------------------------------

def test_submit_blocks_uncertified_finding():
    pol = parse_brief(RICH)
    result = submit.check(_finalized_finding(status=FindingStatus.DRAFT), pol)
    assert not result.ready
    assert "not_finalized" in [i.code for i in result.blockers]


def test_submit_blocks_out_of_scope_at_submission_time():
    pol = parse_brief(RICH)
    f = _finalized_finding(asset="blog.acme.com", endpoint="https://blog.acme.com/x")
    result = submit.check(f, pol)
    assert "out_of_scope" in [i.code for i in result.blockers]


def test_submit_blocks_missing_evidence():
    pol = parse_brief(RICH)
    result = submit.check(_finalized_finding(evidence=[]), pol)
    assert "no_evidence" in [i.code for i in result.blockers]


def test_submit_blocks_poc_when_program_forbids_it():
    pol = parse_brief(POOR)
    f = _finalized_finding(asset="one.tiny.com", endpoint="https://one.tiny.com/a",
                           poc="curl ...")
    assert "poc_not_permitted" in [i.code for i in submit.check(f, pol).blockers]


def test_submit_warns_on_ineligible_class_without_blocking():
    pol = parse_brief(RICH)
    f = _finalized_finding(title="No rate limit on login", vuln_class="rate-limit")
    result = submit.check(f, pol)
    assert "likely_ineligible" in [i.code for i in result.warnings]
    assert "likely_ineligible" not in [i.code for i in result.blockers]


def test_submit_warns_on_blank_impact_but_never_invents_it():
    pol = parse_brief(RICH)
    result = submit.check(_finalized_finding(), pol)
    assert "no_impact" in [i.code for i in result.warnings]
    assert result.ready                      # a warning does not block
    # the renderer omits the section entirely rather than filling it in
    assert "Security Impact" not in result.report_markdown


def test_submit_ready_finding_packages_with_manual_send_instructions():
    pol = parse_brief(RICH)
    text = submit.package(_finalized_finding(), pol, program="Acme", finding_id=7)
    assert "ready for a human to send" in text
    assert "bbagent does not submit" in text
    assert "bbagent submitted 7" in text
    assert "Steps to Reproduce" in text


def test_submit_package_has_no_send_capability():
    # the whole module must not contain an outbound call
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "bbagent", "submit.py")).read()
    for banned in ("urlopen", "requests.", "httpx.", "socket."):
        assert banned not in src, "submit.py must not be able to send: found %s" % banned


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

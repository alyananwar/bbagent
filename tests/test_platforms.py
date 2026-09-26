import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbagent.platforms import fetch
from bbagent import intake

BRIEF = "In scope:\n*.acme.com\nacme.com\nOut of scope:\nadmin.acme.com\n"


def test_detect_platform():
    assert fetch.detect_platform("https://bugcrowd.com/acme") == "bugcrowd"
    assert fetch.detect_platform("https://hackerone.com/acme") == "hackerone"
    assert fetch.detect_platform("https://example.com/x") == ""


def test_html_to_text_strips_scripts():
    html = "<html><body><h1>Scope</h1><script>var x=1</script><p>*.acme.com</p></body></html>"
    text = fetch.html_to_text(html)
    assert "Scope" in text and "*.acme.com" in text and "var x" not in text


def test_fetch_without_network_asks_for_paste():
    brief, note = fetch.fetch_brief("https://bugcrowd.com/acme", allow_network=False)
    assert brief is None and "paste" in note.lower()


def test_fetch_with_injected_fetcher():
    brief, note = fetch.fetch_brief("https://bugcrowd.com/acme", fetcher=lambda u: BRIEF)
    assert brief == BRIEF


def test_import_program_with_raw_text():
    eng, note = intake.import_program("https://bugcrowd.com/acme", raw_text=BRIEF)
    assert eng is not None
    assert eng.platform == "bugcrowd"
    assert eng.status == "awaiting_scope_confirmation"
    values = {r.value for r in eng.policy.in_scope}
    assert "*.acme.com" in values


def test_import_program_no_brief_returns_none():
    eng, note = intake.import_program("https://bugcrowd.com/acme", allow_network=False)
    assert eng is None and note


if __name__ == "__main__":
    from _run import run_module
    import sys as _s
    _s.exit(run_module(_s.modules[__name__]))

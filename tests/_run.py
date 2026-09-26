"""Tiny runner so test files work with plain `python3 tests/test_x.py` and pytest."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_module(mod) -> int:
    tests = [getattr(mod, n) for n in dir(mod) if n.startswith("test_") and callable(getattr(mod, n))]
    failed = 0
    for t in tests:
        try:
            t()
            print("PASS %s" % t.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL %s: %s" % (t.__name__, e))
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("ERROR %s: %r" % (t.__name__, e))
    print("--- %d passed, %d failed ---" % (len(tests) - failed, failed))
    return 1 if failed else 0

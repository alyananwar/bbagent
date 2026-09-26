"""Platform import: turn a program link into a scope brief, safely.

Automated fetching of bug bounty platforms is often restricted by their terms and
frequently needs auth or a real browser. So network fetch is OPT-IN, prints a
ToS warning, and manual paste is always available as the reliable path.
"""

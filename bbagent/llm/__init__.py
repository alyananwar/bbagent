"""LLM layer. Provider-agnostic so the model backend swaps without touching the
rest of the system. The LLM only interprets and drafts. It never authorizes a
target: the deterministic scope engine stays the sole authority.
"""

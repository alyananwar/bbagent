"""Scoped research memory.

Knowledge is stored at a scope so conclusions don't blindly leak between
programs: global | program | target | engagement. Same key at a narrower scope
overrides a broader one when you ask for the merged view.

Backed by its own SQLite table. Small on purpose.
"""
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

SCOPES = ("global", "program", "target", "engagement")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    scope TEXT, scope_key TEXT, key TEXT, value TEXT,
    PRIMARY KEY (scope, scope_key, key)
);
"""


class Memory:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def set(self, scope: str, scope_key: str, key: str, value: Any) -> None:
        if scope not in SCOPES:
            raise ValueError("bad scope: %s" % scope)
        self.conn.execute(
            "INSERT OR REPLACE INTO memory (scope, scope_key, key, value) VALUES (?,?,?,?)",
            (scope, scope_key, key, json.dumps(value)))
        self.conn.commit()

    def get(self, scope: str, scope_key: str, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value FROM memory WHERE scope=? AND scope_key=? AND key=?",
            (scope, scope_key, key)).fetchone()
        return json.loads(row["value"]) if row else default

    def merged(self, key: str, program: str = "", target: str = "", engagement: str = "") -> Any:
        """Return the value for key from the narrowest scope that has it."""
        lookups = [
            ("engagement", engagement), ("target", target),
            ("program", program), ("global", ""),
        ]
        for scope, sk in lookups:
            if scope != "global" and not sk:
                continue
            row = self.conn.execute(
                "SELECT value FROM memory WHERE scope=? AND scope_key=? AND key=?",
                (scope, sk, key)).fetchone()
            if row:
                return json.loads(row["value"])
        return None

    def record_false_positive(self, program: str, fingerprint: str) -> None:
        fps = set(self.get("program", program, "false_positives", []))
        fps.add(fingerprint)
        self.set("program", program, "false_positives", sorted(fps))

    def false_positives(self, program: str) -> List[str]:
        return self.get("program", program, "false_positives", [])

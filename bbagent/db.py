"""SQLite persistence for engagements, findings, evidence, tool runs, and
scope decisions. stdlib sqlite3 only.

Everything is stored as JSON blobs keyed by id + engagement, which keeps the
schema stable while the models evolve. Auditability is the point: every scope
decision and tool run is written so the system can answer "why did it do that?".
"""
import json
import os
import sqlite3
from typing import Dict, List, Optional

from .models import Engagement, Finding, FindingStatus
from . import dedup

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT, platform TEXT, status TEXT, data TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER, fingerprint TEXT, status TEXT, data TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER, tool TEXT, target TEXT, verdict TEXT, data TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS scope_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER, target TEXT, decision TEXT, data TEXT, created_at TEXT
);
"""


class DB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- engagements ---
    def add_engagement(self, eng: Engagement) -> int:
        cur = self.conn.execute(
            "INSERT INTO engagements (program, platform, status, data, created_at) VALUES (?,?,?,?,?)",
            (eng.program, eng.platform, eng.status, json.dumps(eng.to_dict()), eng.created_at),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_engagement(self, eng_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM engagements WHERE id=?", (eng_id,)).fetchone()
        return dict(row) if row else None

    def latest_engagement_id(self) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM engagements ORDER BY id DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    # --- findings ---
    def existing_fingerprints(self, eng_id: int) -> List[str]:
        rows = self.conn.execute(
            "SELECT fingerprint FROM findings WHERE engagement_id=?", (eng_id,)).fetchall()
        return [r["fingerprint"] for r in rows]

    def add_finding(self, eng_id: int, finding: Finding) -> Dict:
        if not finding.fingerprint:
            finding.fingerprint = dedup.fingerprint(finding)
        if dedup.is_duplicate(finding, self.existing_fingerprints(eng_id)):
            finding.status = FindingStatus.DUPLICATE
        cur = self.conn.execute(
            "INSERT INTO findings (engagement_id, fingerprint, status, data, created_at) VALUES (?,?,?,?,?)",
            (eng_id, finding.fingerprint, finding.status.value,
             json.dumps(finding.to_dict()), finding.created_at),
        )
        self.conn.commit()
        return {"id": cur.lastrowid, "status": finding.status.value, "fingerprint": finding.fingerprint}

    def list_findings(self, eng_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE engagement_id=? ORDER BY id", (eng_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_finding(self, finding_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def set_finding_status(self, finding_id: int, status: FindingStatus) -> bool:
        row = self.get_finding(finding_id)
        if not row:
            return False
        if row["status"] == FindingStatus.FINALIZED.value and status != FindingStatus.SUBMITTED:
            return False  # finalized is immutable except to mark submitted
        data = json.loads(row["data"])
        data["status"] = status.value
        self.conn.execute("UPDATE findings SET status=?, data=? WHERE id=?",
                          (status.value, json.dumps(data), finding_id))
        self.conn.commit()
        return True

    # --- provenance logs ---
    def log_scope_decision(self, eng_id: int, decision: Dict) -> None:
        self.conn.execute(
            "INSERT INTO scope_decisions (engagement_id, target, decision, data, created_at) VALUES (?,?,?,?,?)",
            (eng_id, decision.get("target", ""), decision.get("decision", ""),
             json.dumps(decision), decision.get("timestamp", "")),
        )
        self.conn.commit()

    def log_tool_run(self, eng_id: int, run: Dict) -> None:
        self.conn.execute(
            "INSERT INTO tool_runs (engagement_id, tool, target, verdict, data, created_at) VALUES (?,?,?,?,?,?)",
            (eng_id, run.get("tool", ""), run.get("target", ""), run.get("verdict", ""),
             json.dumps(run), run.get("started_at", "")),
        )
        self.conn.commit()

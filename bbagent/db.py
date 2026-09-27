"""SQLite persistence for engagements, findings, evidence, tool runs, and
scope decisions. stdlib sqlite3 only.

Everything is stored as JSON blobs keyed by id + engagement, which keeps the
schema stable while the models evolve. Auditability is the point: every scope
decision and tool run is written so the system can answer "why did it do that?".
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import Engagement, Finding, FindingStatus
from . import dedup


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

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
-- the attack surface is engagement state, not a scratch file: it lives here so a
-- crash mid-run cannot lose discovered endpoints (see save_graph callers).
CREATE TABLE IF NOT EXISTS graphs (
    engagement_id INTEGER PRIMARY KEY, data TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS app_models (
    engagement_id INTEGER PRIMARY KEY, data TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS hypotheses (
    engagement_id INTEGER, hyp_id TEXT, status TEXT, priority REAL, data TEXT,
    created_at TEXT, PRIMARY KEY (engagement_id, hyp_id)
);
CREATE TABLE IF NOT EXISTS blockers (
    engagement_id INTEGER, blocker_id TEXT, kind TEXT, resolved INTEGER, data TEXT,
    created_at TEXT, PRIMARY KEY (engagement_id, blocker_id)
);
CREATE TABLE IF NOT EXISTS research_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER, agent TEXT, hypothesis_id TEXT, data TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS research_state (
    engagement_id INTEGER PRIMARY KEY, state TEXT, data TEXT, updated_at TEXT
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

    # --- research state: surface graph -------------------------------------
    # Persisted after every fold. Previously the graph only reached disk once,
    # at the end of a run, so any failure discarded every discovered endpoint.
    def save_graph(self, eng_id: int, graph_dict: Dict) -> None:
        self.conn.execute(
            "INSERT INTO graphs (engagement_id, data, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(engagement_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (eng_id, json.dumps(graph_dict), _now()))
        self.conn.commit()

    def load_graph(self, eng_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT data FROM graphs WHERE engagement_id=?", (eng_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    # --- research state: application model ---------------------------------
    def save_app_model(self, eng_id: int, model_dict: Dict) -> None:
        self.conn.execute(
            "INSERT INTO app_models (engagement_id, data, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(engagement_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (eng_id, json.dumps(model_dict), _now()))
        self.conn.commit()

    def load_app_model(self, eng_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT data FROM app_models WHERE engagement_id=?", (eng_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    # --- research state: hypotheses ----------------------------------------
    def upsert_hypothesis(self, eng_id: int, hyp: Dict) -> None:
        self.conn.execute(
            "INSERT INTO hypotheses (engagement_id, hyp_id, status, priority, data, created_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(engagement_id, hyp_id) DO UPDATE SET "
            "status=excluded.status, priority=excluded.priority, data=excluded.data",
            (eng_id, hyp["id"], hyp.get("status", ""), float(hyp.get("priority", 0.0)),
             json.dumps(hyp), hyp.get("created_at", "")))
        self.conn.commit()

    def get_hypothesis(self, eng_id: int, hyp_id: str) -> Optional[Dict]:
        row = self.conn.execute("SELECT data FROM hypotheses WHERE engagement_id=? AND hyp_id=?",
                                (eng_id, hyp_id)).fetchone()
        return json.loads(row["data"]) if row else None

    def list_hypotheses(self, eng_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT data FROM hypotheses WHERE engagement_id=? ORDER BY priority DESC, created_at",
            (eng_id,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # --- research state: blockers ------------------------------------------
    def upsert_blocker(self, eng_id: int, blocker: Dict) -> None:
        self.conn.execute(
            "INSERT INTO blockers (engagement_id, blocker_id, kind, resolved, data, created_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(engagement_id, blocker_id) DO UPDATE SET "
            "resolved=excluded.resolved, data=excluded.data",
            (eng_id, blocker["id"], blocker.get("kind", ""), 1 if blocker.get("resolved") else 0,
             json.dumps(blocker), blocker.get("created_at", "")))
        self.conn.commit()

    def get_blocker(self, eng_id: int, blocker_id: str) -> Optional[Dict]:
        row = self.conn.execute("SELECT data FROM blockers WHERE engagement_id=? AND blocker_id=?",
                                (eng_id, blocker_id)).fetchone()
        return json.loads(row["data"]) if row else None

    def list_blockers(self, eng_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT data FROM blockers WHERE engagement_id=? ORDER BY created_at", (eng_id,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # --- research log ------------------------------------------------------
    def append_research_log(self, eng_id: int, entry: Dict) -> None:
        self.conn.execute(
            "INSERT INTO research_log (engagement_id, agent, hypothesis_id, data, created_at) "
            "VALUES (?,?,?,?,?)",
            (eng_id, entry.get("agent", ""), entry.get("hypothesis_id", ""),
             json.dumps(entry), entry.get("timestamp", "")))
        self.conn.commit()

    def list_research_log(self, eng_id: int, limit: Optional[int] = None) -> List[Dict]:
        sql = "SELECT data FROM research_log WHERE engagement_id=? ORDER BY id"
        params: tuple = (eng_id,)
        if limit:
            sql += " DESC LIMIT ?"
            params = (eng_id, limit)
        rows = self.conn.execute(sql, params).fetchall()
        out = [json.loads(r["data"]) for r in rows]
        return list(reversed(out)) if limit else out

    # --- research state pointer --------------------------------------------
    def set_research_state(self, eng_id: int, state: str, extra: Optional[Dict] = None) -> None:
        self.conn.execute(
            "INSERT INTO research_state (engagement_id, state, data, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(engagement_id) DO UPDATE SET state=excluded.state, data=excluded.data, "
            "updated_at=excluded.updated_at",
            (eng_id, state, json.dumps(extra or {}), _now()))
        self.conn.commit()

    def get_research_state(self, eng_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT state, data FROM research_state WHERE engagement_id=?",
                                (eng_id,)).fetchone()
        return {"state": row["state"], "data": json.loads(row["data"])} if row else None

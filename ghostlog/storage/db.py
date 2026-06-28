"""
GhostLog storage layer.
SQLite by default (zero config), swappable for Postgres in production.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostlog.core.models import AgentAction, Incident, ActionStatus, RiskLevel, SystemTouch

DB_PATH = os.getenv("GHOSTLOG_DB", str(Path.home() / ".ghostlog" / "ghostlog.db"))


def _get_conn(path: str = DB_PATH) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS actions (
            action_id      TEXT PRIMARY KEY,
            agent_id       TEXT NOT NULL,
            session_id     TEXT NOT NULL,
            action_type    TEXT NOT NULL,
            description    TEXT NOT NULL,
            inputs         TEXT NOT NULL DEFAULT '{}',
            outputs        TEXT NOT NULL DEFAULT '{}',
            reasoning      TEXT NOT NULL DEFAULT '',
            systems_touched TEXT NOT NULL DEFAULT '[]',
            status         TEXT NOT NULL DEFAULT 'pending',
            risk_level     TEXT NOT NULL DEFAULT 'low',
            timestamp      TEXT NOT NULL,
            duration_ms    REAL NOT NULL DEFAULT 0,
            prev_hash      TEXT NOT NULL DEFAULT '',
            action_hash    TEXT NOT NULL,
            tags           TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_actions_session
            ON actions(session_id);
        CREATE INDEX IF NOT EXISTS idx_actions_agent
            ON actions(agent_id);
        CREATE INDEX IF NOT EXISTS idx_actions_timestamp
            ON actions(timestamp);

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id    TEXT PRIMARY KEY,
            session_id     TEXT NOT NULL,
            agent_id       TEXT NOT NULL,
            title          TEXT NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            severity       TEXT NOT NULL DEFAULT 'medium',
            declared_at    TEXT NOT NULL,
            resolved_at    TEXT,
            root_cause     TEXT NOT NULL DEFAULT '',
            resolution     TEXT NOT NULL DEFAULT '',
            tags           TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_session
            ON incidents(session_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_agent
            ON incidents(agent_id);
    """)
    conn.commit()


def _row_to_action(row: sqlite3.Row) -> AgentAction:
    return AgentAction(
        action_id=row["action_id"],
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        action_type=row["action_type"],
        description=row["description"],
        inputs=json.loads(row["inputs"]),
        outputs=json.loads(row["outputs"]),
        reasoning=row["reasoning"],
        systems_touched=[
            SystemTouch(**t) for t in json.loads(row["systems_touched"])
        ],
        status=ActionStatus(row["status"]),
        risk_level=RiskLevel(row["risk_level"]),
        timestamp=datetime.fromisoformat(row["timestamp"]),
        duration_ms=row["duration_ms"],
        prev_hash=row["prev_hash"],
        action_hash=row["action_hash"],
        tags=json.loads(row["tags"]),
    )


class ActionStore:
    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        conn = _get_conn(db_path)
        _init_db(conn)
        conn.close()

    def save(self, action: AgentAction) -> None:
        conn = _get_conn(self._db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO actions
                (action_id, agent_id, session_id, action_type, description,
                 inputs, outputs, reasoning, systems_touched, status,
                 risk_level, timestamp, duration_ms, prev_hash, action_hash, tags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                action.action_id,
                action.agent_id,
                action.session_id,
                action.action_type,
                action.description,
                json.dumps(action.inputs),
                json.dumps(action.outputs),
                action.reasoning,
                json.dumps([t.model_dump() for t in action.systems_touched]),
                action.status.value,
                action.risk_level.value,
                action.timestamp.isoformat(),
                action.duration_ms,
                action.prev_hash,
                action.action_hash,
                json.dumps(action.tags),
            ))
            conn.commit()
        finally:
            conn.close()

    def get(self, action_id: str) -> AgentAction | None:
        conn = _get_conn(self._db_path)
        try:
            row = conn.execute(
                "SELECT * FROM actions WHERE action_id = ?", (action_id,)
            ).fetchone()
            return _row_to_action(row) if row else None
        finally:
            conn.close()

    def get_by_session(self, session_id: str) -> list[AgentAction]:
        conn = _get_conn(self._db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM actions WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,)
            ).fetchall()
            return [_row_to_action(r) for r in rows]
        finally:
            conn.close()

    def get_by_agent(self, agent_id: str, limit: int = 100) -> list[AgentAction]:
        conn = _get_conn(self._db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM actions WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit)
            ).fetchall()
            return [_row_to_action(r) for r in rows]
        finally:
            conn.close()

    def get_high_risk(self, limit: int = 50) -> list[AgentAction]:
        conn = _get_conn(self._db_path)
        try:
            rows = conn.execute("""
                SELECT * FROM actions
                WHERE risk_level IN ('high', 'critical')
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()
            return [_row_to_action(r) for r in rows]
        finally:
            conn.close()


class IncidentStore:
    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._action_store = ActionStore(db_path)

    def save(self, incident: Incident) -> None:
        conn = _get_conn(self._db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO incidents
                (incident_id, session_id, agent_id, title, description,
                 severity, declared_at, resolved_at, root_cause, resolution, tags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                incident.incident_id,
                incident.session_id,
                incident.agent_id,
                incident.title,
                incident.description,
                incident.severity.value,
                incident.declared_at.isoformat(),
                incident.resolved_at.isoformat() if incident.resolved_at else None,
                incident.root_cause,
                incident.resolution,
                json.dumps(incident.tags),
            ))
            conn.commit()
        finally:
            conn.close()

    def get(self, incident_id: str) -> Incident | None:
        conn = _get_conn(self._db_path)
        try:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return None
            actions = self._action_store.get_by_session(row["session_id"])
            return Incident(
                incident_id=row["incident_id"],
                session_id=row["session_id"],
                agent_id=row["agent_id"],
                title=row["title"],
                description=row["description"],
                severity=RiskLevel(row["severity"]),
                declared_at=datetime.fromisoformat(row["declared_at"]),
                resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
                root_cause=row["root_cause"],
                resolution=row["resolution"],
                tags=json.loads(row["tags"]),
                actions=actions,
            )
        finally:
            conn.close()

    def list_all(self, limit: int = 50) -> list[dict[str, Any]]:
        conn = _get_conn(self._db_path)
        try:
            rows = conn.execute("""
                SELECT incident_id, agent_id, title, severity,
                       declared_at, resolved_at
                FROM incidents ORDER BY declared_at DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def resolve(self, incident_id: str, root_cause: str, resolution: str) -> bool:
        conn = _get_conn(self._db_path)
        try:
            now = datetime.now(timezone.utc).isoformat()
            result = conn.execute("""
                UPDATE incidents
                SET resolved_at=?, root_cause=?, resolution=?
                WHERE incident_id=?
            """, (now, root_cause, resolution, incident_id))
            conn.commit()
            return result.rowcount > 0
        finally:
            conn.close()

-- GhostLog PostgreSQL schema
-- Version: 0.2.0
-- Auto-applied on first docker compose up

CREATE TABLE IF NOT EXISTS actions (
    action_id       TEXT        PRIMARY KEY,
    agent_id        TEXT        NOT NULL,
    session_id      TEXT        NOT NULL,
    action_type     TEXT        NOT NULL,
    description     TEXT        NOT NULL,
    inputs          JSONB       NOT NULL DEFAULT '{}',
    outputs         JSONB       NOT NULL DEFAULT '{}',
    reasoning       TEXT        NOT NULL DEFAULT '',
    systems_touched JSONB       NOT NULL DEFAULT '[]',
    status          TEXT        NOT NULL DEFAULT 'pending',
    risk_level      TEXT        NOT NULL DEFAULT 'low',
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms     FLOAT       NOT NULL DEFAULT 0,
    prev_hash       TEXT        NOT NULL DEFAULT '',
    action_hash     TEXT        NOT NULL,
    tags            TEXT[]      NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_actions_session   ON actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_agent     ON actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_actions_risk      ON actions(risk_level) WHERE risk_level IN ('high','critical');

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT        PRIMARY KEY,
    session_id  TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    title       TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    severity    TEXT        NOT NULL DEFAULT 'medium',
    declared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    root_cause  TEXT        NOT NULL DEFAULT '',
    resolution  TEXT        NOT NULL DEFAULT '',
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    ai_analysis JSONB       -- Claude RCA report stored here
);

CREATE INDEX IF NOT EXISTS idx_incidents_agent      ON incidents(agent_id);
CREATE INDEX IF NOT EXISTS idx_incidents_declared   ON incidents(declared_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_unresolved ON incidents(declared_at DESC) WHERE resolved_at IS NULL;

"""
GhostLog REST API — v0.2
Run with: uvicorn ghostlog.api.main:app --reload

Endpoints:
  GET  /health
  GET  /actions/session/{session_id}
  GET  /actions/agent/{agent_id}
  GET  /actions/high-risk
  GET  /actions/{action_id}
  GET  /actions/{action_id}/blast-radius
  GET  /incidents
  GET  /incidents/{id}
  GET  /incidents/{id}/replay
  GET  /incidents/{id}/blast-radius
  GET  /incidents/{id}/export        ← NEW: OTLP span export
  POST /incidents/{id}/analyze       ← NEW: Claude-powered RCA
  POST /incidents/{id}/resolve
  WS   /ws/incidents                 ← NEW: real-time stream
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ghostlog.core.models import RiskLevel
from ghostlog.storage.db import ActionStore, IncidentStore

_ws_clients: list[WebSocket] = []


async def broadcast(event: str, data: dict[str, Any]) -> None:
    payload = json.dumps({"event": event, **data}, default=str)
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


app = FastAPI(
    title="GhostLog",
    description="AI Agent Incident Response Platform — every decision, logged and chainable.",
    version="0.2.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_actions = ActionStore()
_incidents = IncidentStore()


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ghostlog", "version": "0.2.0"}


# ── WebSocket ──────────────────────────────────────────────────────────────

@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket):
    """Real-time incident stream. Dashboard connects here for live updates."""
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)
    except Exception:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


# ── Actions ────────────────────────────────────────────────────────────────

@app.get("/actions/session/{session_id}")
def get_session_actions(session_id: str) -> list[dict[str, Any]]:
    actions = _actions.get_by_session(session_id)
    return [a.model_dump(mode="json") for a in actions]


@app.get("/actions/agent/{agent_id}")
def get_agent_actions(agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
    actions = _actions.get_by_agent(agent_id, limit=limit)
    return [a.model_dump(mode="json") for a in actions]


@app.get("/actions/high-risk")
def get_high_risk_actions(limit: int = 50) -> list[dict[str, Any]]:
    actions = _actions.get_high_risk(limit=limit)
    return [a.model_dump(mode="json") for a in actions]


@app.get("/actions/{action_id}")
def get_action(action_id: str) -> dict[str, Any]:
    action = _actions.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action.model_dump(mode="json")


@app.get("/actions/{action_id}/blast-radius")
def get_action_blast_radius(action_id: str) -> dict[str, Any]:
    action = _actions.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action.blast_radius()


# ── Incidents ──────────────────────────────────────────────────────────────

@app.get("/incidents")
def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    return _incidents.list_all(limit=limit)


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.model_dump(mode="json")


@app.get("/incidents/{incident_id}/replay")
def replay_incident(incident_id: str) -> dict[str, Any]:
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "incident_id": incident_id,
        "title": incident.title,
        "chain_integrity": incident.chain_integrity,
        "steps": incident.replay(),
    }


@app.get("/incidents/{incident_id}/blast-radius")
def get_incident_blast_radius(incident_id: str) -> dict[str, Any]:
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.full_blast_radius()


@app.get("/incidents/{incident_id}/export")
def export_incident_otlp(incident_id: str) -> dict[str, Any]:
    """
    Export incident as OTLP-compatible span payload.
    Send to Jaeger, Grafana Tempo, Honeycomb, Datadog — any OTel backend.
    AIUC-1 Q2 2026 compliant: cryptographic agent identities included.
    """
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    from ghostlog.otel.export import export_incident
    return export_incident(incident)


@app.post("/incidents/{incident_id}/analyze")
async def analyze_incident_ai(incident_id: str) -> dict[str, Any]:
    """
    Run Claude-powered root cause analysis on this incident.
    Returns structured RCA: root cause, contributing factors, fix, prevention.
    Falls back gracefully if ANTHROPIC_API_KEY is not set.
    """
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    from ghostlog.analysis.ai import analyze_incident
    report = analyze_incident(incident)

    # Broadcast to live dashboard clients
    await broadcast("incident_analyzed", {
        "incident_id": incident_id,
        "root_cause": report.get("root_cause", ""),
        "confidence": report.get("confidence", 0),
        "source": report.get("_source", ""),
    })

    return report


class ResolveRequest(BaseModel):
    root_cause: str
    resolution: str


@app.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, body: ResolveRequest) -> dict[str, Any]:
    ok = _incidents.resolve(incident_id, body.root_cause, body.resolution)
    if not ok:
        raise HTTPException(status_code=404, detail="Incident not found")

    resolved_at = datetime.now(timezone.utc).isoformat()
    await broadcast("incident_resolved", {
        "incident_id": incident_id,
        "resolved_at": resolved_at,
    })
    return {"incident_id": incident_id, "resolved_at": resolved_at, "status": "resolved"}


# ── Dashboard ──────────────────────────────────────────────────────────────
# Serve the marble UI at GET /

from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_STATIC = Path(__file__).parent.parent / "static"

if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

@app.get("/", include_in_schema=False)
def dashboard():
    """Serve the GhostLog dashboard."""
    return FileResponse(str(_STATIC / "dashboard.html"))

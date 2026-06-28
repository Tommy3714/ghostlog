"""
GhostLog OpenTelemetry Exporter.

Converts GhostLog incidents and actions into OTLP-compliant spans.
Plugs into any OTel-compatible backend: Jaeger, Grafana Tempo,
Honeycomb, Datadog, New Relic — without re-instrumenting your code.

AIUC-1 Q2 2026 compliant:
  - Cryptographic agent identity via action_hash chain
  - Per-action span with risk_level, reversibility, and blast metadata
  - Incident spans parent-link individual action spans

Usage:
    from ghostlog.otel.export import export_incident, export_action
    from ghostlog.core.models import Incident

    export_incident(incident)               # sends to OTEL_EXPORTER_OTLP_ENDPOINT
    export_action(action, parent_span_id)   # individual action export
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from ghostlog.core.models import AgentAction, Incident, RiskLevel


# ── OTel attribute names (semantic conventions) ────────────────────────────
# Using ghostlog.* namespace per OTel custom conventions

_ATTR_AGENT_ID        = "ghostlog.agent.id"
_ATTR_SESSION_ID      = "ghostlog.session.id"
_ATTR_INCIDENT_ID     = "ghostlog.incident.id"
_ATTR_ACTION_TYPE     = "ghostlog.action.type"
_ATTR_RISK_LEVEL      = "ghostlog.risk.level"
_ATTR_REVERSIBLE      = "ghostlog.action.reversible"
_ATTR_CHAIN_HASH      = "ghostlog.chain.hash"
_ATTR_CHAIN_PREV_HASH = "ghostlog.chain.prev_hash"
_ATTR_CHAIN_VALID     = "ghostlog.chain.valid"
_ATTR_BLAST_SYSTEMS   = "ghostlog.blast.systems"
_ATTR_BLAST_IRREVERSIBLE = "ghostlog.blast.irreversible"
_ATTR_SEVERITY        = "ghostlog.incident.severity"

_SEVERITY_NUMBER = {
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 13,
    RiskLevel.HIGH: 17,
    RiskLevel.CRITICAL: 21,
}


def export_incident(incident: Incident) -> dict[str, Any]:
    """
    Export a full incident as a parent span with child action spans.
    Returns the OTLP JSON payload (also sends it if endpoint configured).
    """
    incident_span_id = _new_span_id()
    trace_id = _session_to_trace_id(incident.session_id)

    action_spans = []
    for action in incident.actions:
        span = _action_to_span(
            action=action,
            trace_id=trace_id,
            parent_span_id=incident_span_id,
        )
        action_spans.append(span)

    # Parent incident span
    start_ns = int(incident.declared_at.timestamp() * 1e9)
    end_ns = (
        int(incident.resolved_at.timestamp() * 1e9)
        if incident.resolved_at
        else int(time.time() * 1e9)
    )

    incident_span = {
        "traceId": trace_id,
        "spanId": incident_span_id,
        "name": f"ghostlog.incident/{incident.title}",
        "kind": 2,  # SPAN_KIND_SERVER
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": [
            _attr("string", _ATTR_AGENT_ID, incident.agent_id),
            _attr("string", _ATTR_SESSION_ID, incident.session_id),
            _attr("string", _ATTR_INCIDENT_ID, incident.incident_id),
            _attr("string", _ATTR_SEVERITY, incident.severity.value),
            _attr("bool", _ATTR_BLAST_IRREVERSIBLE, not incident.full_blast_radius()["can_fully_rollback"]),
            _attr("bool", _ATTR_CHAIN_VALID, incident.chain_integrity),
            _attr("string", "ghostlog.incident.root_cause", incident.root_cause or ""),
            _attr("string", "ghostlog.incident.resolution", incident.resolution or ""),
        ],
        "status": {
            "code": 2 if incident.severity == RiskLevel.CRITICAL else 1,
            "message": incident.root_cause or incident.title,
        },
        "events": [
            {
                "name": "incident.declared",
                "timeUnixNano": str(start_ns),
                "attributes": [_attr("string", "severity", incident.severity.value)],
            }
        ] + ([
            {
                "name": "incident.resolved",
                "timeUnixNano": str(int(incident.resolved_at.timestamp() * 1e9)),
                "attributes": [_attr("string", "resolution", incident.resolution)],
            }
        ] if incident.resolved_at else []),
        "childSpans": action_spans,
    }

    payload = _build_otlp_payload(trace_id, [incident_span] + action_spans)
    _send_if_configured(payload)
    return payload


def export_action(action: AgentAction, parent_span_id: str | None = None) -> dict[str, Any]:
    """Export a single action as an OTLP span."""
    trace_id = _session_to_trace_id(action.session_id)
    span = _action_to_span(action, trace_id, parent_span_id or "")
    payload = _build_otlp_payload(trace_id, [span])
    _send_if_configured(payload)
    return payload


# ── Internal helpers ───────────────────────────────────────────────────────

def _action_to_span(
    action: AgentAction,
    trace_id: str,
    parent_span_id: str,
) -> dict[str, Any]:
    start_ns = int(action.timestamp.timestamp() * 1e9)
    end_ns   = start_ns + int(action.duration_ms * 1e6)

    systems = list({t.system for t in action.systems_touched})
    irreversible = action.has_irreversible_touches

    attrs = [
        _attr("string", _ATTR_AGENT_ID,        action.agent_id),
        _attr("string", _ATTR_SESSION_ID,       action.session_id),
        _attr("string", _ATTR_ACTION_TYPE,      action.action_type),
        _attr("string", _ATTR_RISK_LEVEL,       action.risk_level.value),
        _attr("bool",   _ATTR_REVERSIBLE,       not irreversible),
        _attr("string", _ATTR_CHAIN_HASH,       action.action_hash),
        _attr("string", _ATTR_CHAIN_PREV_HASH,  action.prev_hash),
        _attr("bool",   _ATTR_CHAIN_VALID,      True),  # verified on ingest
        _attr("string", _ATTR_BLAST_SYSTEMS,    json.dumps(systems)),
        _attr("bool",   _ATTR_BLAST_IRREVERSIBLE, irreversible),
        _attr("string", "ghostlog.action.reasoning", action.reasoning),
        _attr("int",    "ghostlog.action.severity_number", _SEVERITY_NUMBER[action.risk_level]),
    ]

    return {
        "traceId": trace_id,
        "spanId": _new_span_id(),
        "parentSpanId": parent_span_id,
        "name": f"ghostlog.action/{action.action_type}/{action.description[:60]}",
        "kind": 3,  # SPAN_KIND_CLIENT
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": attrs,
        "status": {
            "code": 2 if action.risk_level == RiskLevel.CRITICAL else 1,
            "message": action.description,
        },
    }


def _build_otlp_payload(trace_id: str, spans: list[dict]) -> dict[str, Any]:
    return {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    _attr("string", "service.name", "ghostlog"),
                    _attr("string", "service.version", "0.1.0"),
                    _attr("string", "telemetry.sdk.name", "ghostlog-otel"),
                    _attr("string", "ghostlog.compliance", "AIUC-1-Q2-2026"),
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "ghostlog.otel", "version": "0.1.0"},
                "spans": spans,
            }]
        }]
    }


def _send_if_configured(payload: dict[str, Any]) -> None:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    if not endpoint:
        return
    try:
        import urllib.request
        url = endpoint.rstrip("/") + "/v1/traces"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception as exc:
        print(f"[ghostlog/otel] Export failed: {exc}")


def _attr(type_: str, key: str, value: Any) -> dict[str, Any]:
    type_map = {
        "string": {"stringValue": str(value)},
        "bool":   {"boolValue": bool(value)},
        "int":    {"intValue": int(value)},
    }
    return {"key": key, "value": type_map[type_]}


def _new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def _session_to_trace_id(session_id: str) -> str:
    """Deterministic trace ID from session — same session = same trace."""
    import hashlib
    return hashlib.md5(session_id.encode()).hexdigest()

"""
GhostLog AI Analysis Engine.

When an incident is declared, Claude automatically analyzes the full
decision chain and returns a structured root cause report.

No other open-source agent observability tool does this.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ghostlog.core.models import Incident, RiskLevel


_SYSTEM_PROMPT = """You are GhostLog's incident analysis engine.
You receive a structured AI agent incident — a full decision chain with
hash-linked actions, blast radius data, and system touches.

Your job: produce a precise, actionable root cause analysis.
No fluff. No hedging. Specific, technical, fixable.

Respond ONLY with valid JSON. No markdown, no preamble, no backticks.
"""

_ANALYSIS_SCHEMA = {
    "root_cause": "One precise sentence. What went wrong and why.",
    "failed_at_step": "integer — the step number where the failure originated",
    "contributing_factors": ["list of strings — 2-4 specific factors"],
    "blast_summary": "One sentence summarizing the damage",
    "recommended_fix": ["list of strings — ordered, actionable steps"],
    "prevention": ["list of strings — architectural or process changes"],
    "recurrence_risk": "low | medium | high",
    "confidence": "float 0.0–1.0",
    "estimated_fix_hours": "integer — rough engineer-hours to resolve",
}


def analyze_incident(incident: Incident) -> dict[str, Any]:
    """
    Run Claude analysis on a declared incident.
    Returns structured RCA report. Falls back gracefully if API unavailable.

    Usage:
        from ghostlog.analysis.ai import analyze_incident
        report = analyze_incident(incident)
    """
    try:
        return _run_analysis(incident)
    except Exception as exc:
        return _fallback_report(incident, error=str(exc))


def _run_analysis(incident: Incident) -> dict[str, Any]:
    import anthropic

    client = anthropic.Anthropic(
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )

    replay = incident.replay()
    blast  = incident.full_blast_radius()

    user_prompt = f"""Analyze this AI agent incident.

INCIDENT: {incident.title}
AGENT: {incident.agent_id}
SESSION: {incident.session_id}
SEVERITY: {incident.severity.value.upper()}
CHAIN INTEGRITY: {"VALID" if incident.chain_integrity else "COMPROMISED"}

DECISION CHAIN ({len(replay)} steps):
{json.dumps(replay, indent=2, default=str)}

BLAST RADIUS:
{json.dumps(blast, indent=2)}

Required output schema:
{json.dumps(_ANALYSIS_SCHEMA, indent=2)}
"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw = response.content[0].text.strip()

    # Strip any accidental markdown fences
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip().strip("```")

    report = json.loads(raw)
    report["_source"] = "claude-sonnet-4-6"
    report["_incident_id"] = incident.incident_id
    return report


def _fallback_report(incident: Incident, error: str = "") -> dict[str, Any]:
    """
    Best-effort static analysis when the API is unavailable.
    Still useful — surfaces the highest-risk step and blast info.
    """
    replay = incident.replay()
    blast  = incident.full_blast_radius()

    # Find the step with highest risk
    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    worst = max(replay, key=lambda s: risk_order.get(s.get("risk_level", "low"), 0))

    irreversible = [
        s for s in replay
        if not s.get("blast", {}).get("can_fully_rollback", True)
        or s.get("blast", {}).get("irreversible", False)
    ]

    return {
        "root_cause": f"Failure originated at step {worst['step']}: {worst['description']}",
        "failed_at_step": worst["step"],
        "contributing_factors": [
            f"{len(irreversible)} irreversible action(s) detected",
            f"{blast['total_resources_touched']} resource(s) touched across {len(blast['systems_affected'])} system(s)",
            "Chain integrity: " + ("valid" if incident.chain_integrity else "COMPROMISED — possible tampering"),
        ],
        "blast_summary": f"Affected systems: {', '.join(blast['systems_affected'])}. Rollback possible: {blast['can_fully_rollback']}",
        "recommended_fix": [
            "Review step " + str(worst["step"]) + " in the replay for the root decision",
            "Audit context variable resolution before irreversible actions",
            "Add pre-flight validation on destructive operations",
        ],
        "prevention": [
            "Require explicit confirmation step before DELETE/irreversible operations",
            "Validate all resolved IDs against the current request context, not session cache",
        ],
        "recurrence_risk": "high" if incident.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "medium",
        "confidence": 0.4,
        "estimated_fix_hours": 2,
        "_source": "ghostlog-static-fallback",
        "_error": error,
        "_incident_id": incident.incident_id,
    }

"""
GhostLog alert dispatcher.
Fires on irreversible actions, incident declarations, and critical risk events.
Zero required config — falls back to console. Plug in webhooks or email as needed.
"""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any


_WEBHOOK_URL = os.getenv("GHOSTLOG_WEBHOOK_URL", "")
_ALERT_EMAIL = os.getenv("GHOSTLOG_ALERT_EMAIL", "")


def dispatch(event: str, message: str, **payload: Any) -> None:
    """
    Route an alert to all configured channels.
    Always prints to console. Optionally fires webhook.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # Serialize any Pydantic models in payload
    clean_payload: dict[str, Any] = {"event": event, "message": message, "timestamp": timestamp}
    for k, v in payload.items():
        try:
            clean_payload[k] = v.model_dump() if hasattr(v, "model_dump") else str(v)
        except Exception:
            clean_payload[k] = str(v)

    _console(event, message, timestamp)

    if _WEBHOOK_URL:
        _webhook(clean_payload)


def _console(event: str, message: str, timestamp: str) -> None:
    prefix = {
        "irreversible_action": "⚠️  IRREVERSIBLE",
        "incident_declared":   "🚨 INCIDENT",
        "critical_risk":       "🔴 CRITICAL",
    }.get(event, "ℹ️  GHOSTLOG")

    print(f"\n{prefix} [{timestamp}]\n  {message}\n")


def _webhook(payload: dict[str, Any]) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            _WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status not in (200, 201, 204):
                print(f"[ghostlog] Webhook returned {resp.status}")
    except Exception as exc:
        print(f"[ghostlog] Webhook failed: {exc}")

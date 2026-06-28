"""
GhostLog core data models.
Every agent action is a first-class event — logged, hashed, chained.
"""

from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, model_validator


class ActionStatus(str, Enum):
    PENDING   = "pending"
    SUCCESS   = "success"
    FAILED    = "failed"
    ROLLED_BACK = "rolled_back"


class RiskLevel(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"
    CRITICAL = "critical"


class SystemTouch(BaseModel):
    """A single system or resource touched by an agent action."""
    system: str                        # e.g. "postgres", "s3", "filesystem"
    resource: str                      # e.g. "users table", "bucket/key"
    operation: str                     # e.g. "READ", "WRITE", "DELETE"
    reversible: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentAction(BaseModel):
    """
    A single atomic action taken by an AI agent.
    Hash-chained to the previous action for tamper evidence.
    """
    action_id: str
    agent_id: str
    session_id: str
    action_type: str                   # e.g. "tool_call", "decision", "api_call"
    description: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""                # Why the agent made this decision
    systems_touched: list[SystemTouch] = Field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    risk_level: RiskLevel = RiskLevel.LOW
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    prev_hash: str = ""                # Hash of the previous action in chain
    action_hash: str = ""             # This action's hash (computed on creation)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_hash(self) -> "AgentAction":
        if not self.action_hash:
            payload = json.dumps({
                "action_id": self.action_id,
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "action_type": self.action_type,
                "description": self.description,
                "inputs": self.inputs,
                "timestamp": self.timestamp.isoformat(),
                "prev_hash": self.prev_hash,
            }, sort_keys=True)
            self.action_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self

    @property
    def has_irreversible_touches(self) -> bool:
        return any(not t.reversible for t in self.systems_touched)

    def blast_radius(self) -> dict[str, Any]:
        """Summarize the blast radius of this action."""
        return {
            "action_id": self.action_id,
            "systems": [t.system for t in self.systems_touched],
            "resources_touched": len(self.systems_touched),
            "irreversible": self.has_irreversible_touches,
            "risk_level": self.risk_level,
            "reversible_count": sum(1 for t in self.systems_touched if t.reversible),
            "irreversible_count": sum(1 for t in self.systems_touched if not t.reversible),
        }


class Incident(BaseModel):
    """
    A declared incident — a session where something went wrong.
    Contains the full action chain for replay.
    """
    incident_id: str
    session_id: str
    agent_id: str
    title: str
    description: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM
    declared_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    actions: list[AgentAction] = Field(default_factory=list)
    root_cause: str = ""
    resolution: str = ""
    tags: list[str] = Field(default_factory=list)

    @property
    def is_resolved(self) -> bool:
        return self.resolved_at is not None

    @property
    def duration_seconds(self) -> float | None:
        if self.resolved_at:
            return (self.resolved_at - self.declared_at).total_seconds()
        return None

    def full_blast_radius(self) -> dict[str, Any]:
        """Aggregate blast radius across ALL actions in this incident."""
        all_systems: set[str] = set()
        all_resources: list[str] = []
        irreversible_action_ids: set[str] = set()

        for action in self.actions:
            for touch in action.systems_touched:
                all_systems.add(touch.system)
                all_resources.append(f"{touch.system}:{touch.resource}")
                if not touch.reversible:
                    irreversible_action_ids.add(action.action_id)

        irreversible_actions = list(irreversible_action_ids)

        return {
            "incident_id": self.incident_id,
            "total_actions": len(self.actions),
            "systems_affected": sorted(all_systems),
            "total_resources_touched": len(all_resources),
            "irreversible_action_ids": irreversible_actions,
            "can_fully_rollback": len(irreversible_actions) == 0,
            "severity": self.severity,
        }

    def replay(self) -> list[dict[str, Any]]:
        """Return ordered action replay with chain verification."""
        replayed = []
        prev_hash = ""
        chain_valid = True

        for i, action in enumerate(self.actions):
            hash_ok = action.prev_hash == prev_hash
            if not hash_ok:
                chain_valid = False

            replayed.append({
                "step": i + 1,
                "action_id": action.action_id,
                "timestamp": action.timestamp.isoformat(),
                "action_type": action.action_type,
                "description": action.description,
                "reasoning": action.reasoning,
                "status": action.status,
                "risk_level": action.risk_level,
                "blast": action.blast_radius(),
                "chain_valid": hash_ok,
            })
            prev_hash = action.action_hash

        return replayed

    @property
    def chain_integrity(self) -> bool:
        """Verify the entire action chain is untampered."""
        prev_hash = ""
        for action in self.actions:
            if action.prev_hash != prev_hash:
                return False
            prev_hash = action.action_hash
        return True


class AlertConfig(BaseModel):
    """Alert routing configuration."""
    webhook_url: str | None = None
    email: str | None = None
    min_severity: RiskLevel = RiskLevel.HIGH
    on_irreversible_action: bool = True
    on_incident_declared: bool = True

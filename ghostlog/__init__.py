"""
GhostLog — AI Agent Incident Response Platform.

Quick start:
    from ghostlog import GhostTracer, RiskLevel

    tracer = GhostTracer(agent_id="my-agent")

    @tracer.trace(action_type="db_write", risk_level=RiskLevel.HIGH)
    def write_to_database(data: dict) -> dict:
        ...

    async with tracer.action("Delete record", risk_level=RiskLevel.CRITICAL) as ctx:
        ctx.touch("postgres", "users", "DELETE", reversible=False)
        ctx.record_reasoning("User requested account deletion")
        ...

    incident_id = tracer.declare_incident("Agent deleted wrong records")
"""

from ghostlog.core.models import (
    ActionStatus,
    AgentAction,
    AlertConfig,
    Incident,
    RiskLevel,
    SystemTouch,
)
from ghostlog.core.tracer import GhostTracer, ActionContext

__all__ = [
    "GhostTracer",
    "ActionContext",
    "AgentAction",
    "Incident",
    "SystemTouch",
    "RiskLevel",
    "ActionStatus",
    "AlertConfig",
]

__version__ = "0.1.0"

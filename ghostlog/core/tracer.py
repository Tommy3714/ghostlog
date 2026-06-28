"""
GhostLog tracer — wrap any agent function and get full observability.

Usage:
    from ghostlog import GhostTracer

    tracer = GhostTracer(agent_id="my-agent")

    @tracer.trace(action_type="tool_call", systems=[...])
    async def call_database(query: str) -> dict:
        ...

    # Or wrap inline:
    async with tracer.action("Delete user record", risk=RiskLevel.HIGH) as act:
        result = await db.delete(user_id)
        act.record_output(result)
        act.touch("postgres", "users", "DELETE", reversible=False)
"""

from __future__ import annotations

import asyncio
import functools
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Callable

from ghostlog.core.models import (
    ActionStatus,
    AgentAction,
    RiskLevel,
    SystemTouch,
)
from ghostlog.storage.db import ActionStore


class ActionContext:
    """
    Live context for a single agent action.
    Passed into decorated functions so they can record outputs,
    reasoning, and system touches mid-execution.
    """

    def __init__(self, action: AgentAction, store: ActionStore):
        self._action = action
        self._store = store

    @property
    def action_id(self) -> str:
        return self._action.action_id

    def record_reasoning(self, text: str) -> None:
        self._action.reasoning = text

    def record_output(self, output: Any) -> None:
        self._action.outputs = output if isinstance(output, dict) else {"result": output}

    def touch(
        self,
        system: str,
        resource: str,
        operation: str,
        reversible: bool = True,
        **metadata: Any,
    ) -> None:
        self._action.systems_touched.append(
            SystemTouch(
                system=system,
                resource=resource,
                operation=operation,
                reversible=reversible,
                metadata=metadata,
            )
        )

    def tag(self, *tags: str) -> None:
        self._action.tags.extend(tags)

    def set_risk(self, level: RiskLevel) -> None:
        self._action.risk_level = level


class GhostTracer:
    """
    Per-agent tracer. One tracer per agent instance.
    Maintains session state and action chain.
    """

    def __init__(
        self,
        agent_id: str,
        session_id: str | None = None,
        store: ActionStore | None = None,
        alert_on_irreversible: bool = True,
    ):
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self._store = store or ActionStore()
        self._prev_hash = ""
        self._alert_on_irreversible = alert_on_irreversible

    def _make_action(
        self,
        action_type: str,
        description: str,
        inputs: dict[str, Any],
        risk_level: RiskLevel,
    ) -> AgentAction:
        action = AgentAction(
            action_id=str(uuid.uuid4()),
            agent_id=self.agent_id,
            session_id=self.session_id,
            action_type=action_type,
            description=description,
            inputs=inputs,
            risk_level=risk_level,
            prev_hash=self._prev_hash,
        )
        return action

    def _finalize(self, action: AgentAction, elapsed_ms: float, success: bool) -> None:
        action.duration_ms = elapsed_ms
        action.status = ActionStatus.SUCCESS if success else ActionStatus.FAILED
        self._store.save(action)
        self._prev_hash = action.action_hash

        if self._alert_on_irreversible and action.has_irreversible_touches:
            self._fire_irreversible_alert(action)

    def _fire_irreversible_alert(self, action: AgentAction) -> None:
        # Pluggable — alerts module hooks in here
        from ghostlog.alerts.notify import dispatch
        dispatch(
            event="irreversible_action",
            action=action,
            message=(
                f"⚠️  Agent '{self.agent_id}' took an IRREVERSIBLE action: "
                f"{action.description}"
            ),
        )

    # ── Decorator ──────────────────────────────────────────────────────────

    def trace(
        self,
        action_type: str = "tool_call",
        description: str | None = None,
        risk_level: RiskLevel = RiskLevel.LOW,
    ):
        """
        Decorator for tracing agent functions.

            @tracer.trace(action_type="db_write", risk_level=RiskLevel.HIGH)
            async def write_record(data: dict) -> dict:
                ...
        """
        def decorator(fn: Callable):
            desc = description or fn.__doc__ or fn.__name__

            if asyncio.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    action = self._make_action(
                        action_type=action_type,
                        description=desc,
                        inputs={"args": str(args), "kwargs": str(kwargs)},
                        risk_level=risk_level,
                    )
                    t0 = time.perf_counter()
                    try:
                        result = await fn(*args, **kwargs)
                        action.outputs = result if isinstance(result, dict) else {"result": str(result)}
                        self._finalize(action, (time.perf_counter() - t0) * 1000, success=True)
                        return result
                    except Exception as exc:
                        self._finalize(action, (time.perf_counter() - t0) * 1000, success=False)
                        raise
                return async_wrapper
            else:
                @functools.wraps(fn)
                def sync_wrapper(*args, **kwargs):
                    action = self._make_action(
                        action_type=action_type,
                        description=desc,
                        inputs={"args": str(args), "kwargs": str(kwargs)},
                        risk_level=risk_level,
                    )
                    t0 = time.perf_counter()
                    try:
                        result = fn(*args, **kwargs)
                        action.outputs = result if isinstance(result, dict) else {"result": str(result)}
                        self._finalize(action, (time.perf_counter() - t0) * 1000, success=True)
                        return result
                    except Exception as exc:
                        self._finalize(action, (time.perf_counter() - t0) * 1000, success=False)
                        raise
                return sync_wrapper
        return decorator

    # ── Context managers ───────────────────────────────────────────────────

    @asynccontextmanager
    async def action(
        self,
        description: str,
        action_type: str = "action",
        risk_level: RiskLevel = RiskLevel.LOW,
        inputs: dict[str, Any] | None = None,
    ):
        """
        Async context manager for manual action tracing.

            async with tracer.action("Delete user", risk=RiskLevel.CRITICAL) as ctx:
                ctx.touch("postgres", "users", "DELETE", reversible=False)
                await db.delete(user_id)
        """
        ag_action = self._make_action(
            action_type=action_type,
            description=description,
            inputs=inputs or {},
            risk_level=risk_level,
        )
        ctx = ActionContext(ag_action, self._store)
        t0 = time.perf_counter()
        try:
            yield ctx
            self._finalize(ag_action, (time.perf_counter() - t0) * 1000, success=True)
        except Exception:
            self._finalize(ag_action, (time.perf_counter() - t0) * 1000, success=False)
            raise

    @contextmanager
    def sync_action(
        self,
        description: str,
        action_type: str = "action",
        risk_level: RiskLevel = RiskLevel.LOW,
        inputs: dict[str, Any] | None = None,
    ):
        """Sync version of the action context manager."""
        ag_action = self._make_action(
            action_type=action_type,
            description=description,
            inputs=inputs or {},
            risk_level=risk_level,
        )
        ctx = ActionContext(ag_action, self._store)
        t0 = time.perf_counter()
        try:
            yield ctx
            self._finalize(ag_action, (time.perf_counter() - t0) * 1000, success=True)
        except Exception:
            self._finalize(ag_action, (time.perf_counter() - t0) * 1000, success=False)
            raise

    # ── Session helpers ────────────────────────────────────────────────────

    def get_session_actions(self) -> list[AgentAction]:
        return self._store.get_by_session(self.session_id)

    def declare_incident(self, title: str, severity: RiskLevel = RiskLevel.HIGH) -> str:
        """Declare an incident from the current session. Returns incident_id."""
        from ghostlog.storage.db import IncidentStore
        from ghostlog.core.models import Incident

        incident = Incident(
            incident_id=str(uuid.uuid4()),
            session_id=self.session_id,
            agent_id=self.agent_id,
            title=title,
            severity=severity,
            actions=self.get_session_actions(),
        )
        IncidentStore().save(incident)

        from ghostlog.alerts.notify import dispatch
        dispatch(
            event="incident_declared",
            incident=incident,
            message=f"🚨 Incident declared: {title} | Agent: {self.agent_id}",
        )
        return incident.incident_id

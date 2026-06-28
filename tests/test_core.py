"""
GhostLog core tests.
Run with: pytest tests/ -v
"""

import pytest
import uuid
import asyncio
from ghostlog import GhostTracer, RiskLevel
from ghostlog.core.models import AgentAction, Incident, SystemTouch, ActionStatus
from ghostlog.storage.db import ActionStore, IncidentStore
import tempfile, os


@pytest.fixture
def tmp_db(tmp_path):
    """Isolated temp DB per test."""
    return str(tmp_path / "test.db")


@pytest.fixture
def tracer(tmp_db):
    store = ActionStore(db_path=tmp_db)
    from ghostlog.storage.db import IncidentStore as IS
    t = GhostTracer(
        agent_id="test-agent",
        session_id=str(uuid.uuid4()),
        store=store,
        alert_on_irreversible=False,  # silence alerts in tests
    )
    return t, tmp_db


# ── Model tests ────────────────────────────────────────────────────────────

def test_action_hash_computed():
    action = AgentAction(
        action_id=str(uuid.uuid4()),
        agent_id="agent-1",
        session_id="sess-1",
        action_type="test",
        description="A test action",
    )
    assert len(action.action_hash) == 64  # SHA-256 hex


def test_action_hash_changes_with_content():
    base = dict(
        agent_id="agent-1",
        session_id="sess-1",
        action_type="test",
        description="test",
    )
    a1 = AgentAction(action_id=str(uuid.uuid4()), **base)
    a2 = AgentAction(action_id=str(uuid.uuid4()), **base)
    assert a1.action_hash != a2.action_hash  # different action_ids


def test_chain_links():
    a1 = AgentAction(
        action_id=str(uuid.uuid4()),
        agent_id="a", session_id="s",
        action_type="t", description="first",
        prev_hash="",
    )
    a2 = AgentAction(
        action_id=str(uuid.uuid4()),
        agent_id="a", session_id="s",
        action_type="t", description="second",
        prev_hash=a1.action_hash,
    )
    assert a2.prev_hash == a1.action_hash


def test_blast_radius_irreversible():
    action = AgentAction(
        action_id=str(uuid.uuid4()),
        agent_id="a", session_id="s",
        action_type="delete", description="delete user",
        systems_touched=[
            SystemTouch(system="postgres", resource="users", operation="DELETE", reversible=False),
            SystemTouch(system="s3", resource="uploads/", operation="DELETE", reversible=False),
            SystemTouch(system="cache", resource="user:42", operation="DEL", reversible=True),
        ],
    )
    br = action.blast_radius()
    assert br["irreversible"] is True
    assert br["irreversible_count"] == 2
    assert br["reversible_count"] == 1
    assert br["resources_touched"] == 3


# ── Storage tests ──────────────────────────────────────────────────────────

def test_action_store_save_and_get(tmp_db):
    store = ActionStore(db_path=tmp_db)
    action = AgentAction(
        action_id=str(uuid.uuid4()),
        agent_id="agent-1",
        session_id="sess-1",
        action_type="test",
        description="stored action",
    )
    store.save(action)
    retrieved = store.get(action.action_id)
    assert retrieved is not None
    assert retrieved.action_id == action.action_id
    assert retrieved.action_hash == action.action_hash


def test_action_store_session_order(tmp_db):
    store = ActionStore(db_path=tmp_db)
    sess = str(uuid.uuid4())
    ids = []
    prev = ""
    for i in range(5):
        a = AgentAction(
            action_id=str(uuid.uuid4()),
            agent_id="agent-1",
            session_id=sess,
            action_type="step",
            description=f"step {i}",
            prev_hash=prev,
        )
        store.save(a)
        prev = a.action_hash
        ids.append(a.action_id)

    actions = store.get_by_session(sess)
    assert len(actions) == 5
    assert [a.action_id for a in actions] == ids


# ── Tracer tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tracer_async_context(tracer):
    t, db = tracer
    async with t.action("test action", risk_level=RiskLevel.LOW) as ctx:
        ctx.touch("postgres", "test_table", "READ")
        ctx.record_reasoning("just a test")

    actions = t.get_session_actions()
    assert len(actions) == 1
    assert actions[0].status == ActionStatus.SUCCESS
    assert actions[0].reasoning == "just a test"
    assert len(actions[0].systems_touched) == 1


@pytest.mark.asyncio
async def test_tracer_chain_integrity(tracer):
    t, db = tracer
    for i in range(4):
        async with t.action(f"action {i}") as ctx:
            ctx.record_output({"step": i})

    actions = t.get_session_actions()
    assert len(actions) == 4
    # Verify chain manually
    prev = ""
    for a in actions:
        assert a.prev_hash == prev
        prev = a.action_hash


@pytest.mark.asyncio
async def test_tracer_records_failure(tracer):
    t, db = tracer
    try:
        async with t.action("failing action") as ctx:
            raise ValueError("boom")
    except ValueError:
        pass

    actions = t.get_session_actions()
    assert actions[0].status == ActionStatus.FAILED


# ── Incident tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_incident_replay_and_chain(tracer):
    t, db = tracer
    for i in range(3):
        async with t.action(f"step {i}", risk_level=RiskLevel.MEDIUM) as ctx:
            ctx.touch("db", f"table_{i}", "WRITE")

    from ghostlog.core.models import Incident
    from ghostlog.storage.db import IncidentStore
    inc = Incident(
        incident_id=str(uuid.uuid4()),
        session_id=t.session_id,
        agent_id=t.agent_id,
        title="Test incident",
        actions=t.get_session_actions(),
    )
    istore = IncidentStore(db_path=db)
    istore.save(inc)

    retrieved = istore.get(inc.incident_id)
    assert retrieved.chain_integrity is True
    replay = retrieved.replay()
    assert len(replay) == 3
    assert all(s["chain_valid"] for s in replay)


@pytest.mark.asyncio
async def test_full_blast_radius(tracer):
    t, db = tracer
    async with t.action("safe read") as ctx:
        ctx.touch("postgres", "users", "SELECT", reversible=True)

    async with t.action("nuke it") as ctx:
        ctx.touch("postgres", "users", "DELETE", reversible=False)
        ctx.touch("s3", "backups/", "DELETE", reversible=False)

    from ghostlog.core.models import Incident
    from ghostlog.storage.db import IncidentStore
    inc = Incident(
        incident_id=str(uuid.uuid4()),
        session_id=t.session_id,
        agent_id=t.agent_id,
        title="Blast test",
        actions=t.get_session_actions(),
    )
    br = inc.full_blast_radius()
    assert br["can_fully_rollback"] is False
    assert len(br["irreversible_action_ids"]) == 1
    assert set(br["systems_affected"]) == {"postgres", "s3"}

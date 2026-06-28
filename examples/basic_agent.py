"""
GhostLog example — simulates an AI agent making a series of decisions,
including one irreversible action that triggers an alert,
then declares an incident and replays the chain.

Run with:
    python examples/basic_agent.py
"""

import asyncio
import uuid
from ghostlog import GhostTracer, RiskLevel


async def main():
    session_id = str(uuid.uuid4())
    tracer = GhostTracer(agent_id="example-agent", session_id=session_id)

    print("=" * 60)
    print("  GhostLog — AI Agent Incident Response Demo")
    print("=" * 60)

    # Step 1: A safe read operation
    async with tracer.action(
        "Fetch user record",
        action_type="db_read",
        risk_level=RiskLevel.LOW,
        inputs={"user_id": "usr_42"},
    ) as ctx:
        ctx.touch("postgres", "users", "READ", reversible=True)
        ctx.record_reasoning("Agent needs user data to process request")
        ctx.record_output({"user_id": "usr_42", "email": "alice@example.com"})

    print("✓  Step 1: Read user record (safe)")

    # Step 2: Write operation — medium risk
    async with tracer.action(
        "Update user subscription tier",
        action_type="db_write",
        risk_level=RiskLevel.MEDIUM,
        inputs={"user_id": "usr_42", "new_tier": "pro"},
    ) as ctx:
        ctx.touch("postgres", "subscriptions", "UPDATE", reversible=True)
        ctx.touch("stripe", "customer/cus_xyz", "UPDATE", reversible=True)
        ctx.record_reasoning("User requested upgrade via chat; confirmed intent")
        ctx.record_output({"status": "updated", "tier": "pro"})

    print("✓  Step 2: Updated subscription (reversible)")

    # Step 3: IRREVERSIBLE — this fires an alert
    async with tracer.action(
        "Permanently delete user data — GDPR request",
        action_type="db_delete",
        risk_level=RiskLevel.CRITICAL,
        inputs={"user_id": "usr_WRONG"},   # <-- agent got the wrong user!
    ) as ctx:
        ctx.touch("postgres", "users", "DELETE", reversible=False)
        ctx.touch("s3", "user-uploads/usr_WRONG/", "DELETE", reversible=False)
        ctx.touch("postgres", "audit_logs", "DELETE", reversible=False)
        ctx.record_reasoning("Agent misread user_id from context; deleted wrong record")
        ctx.tag("gdpr", "data-deletion", "wrong-target")

    print("⚠️   Step 3: Irreversible delete fired — alert dispatched")

    # Declare the incident
    incident_id = tracer.declare_incident(
        title="Agent deleted wrong user — GDPR workflow error",
        severity=RiskLevel.CRITICAL,
    )
    print(f"\n🚨 Incident declared: {incident_id}")

    # Replay the incident
    from ghostlog.storage.db import IncidentStore
    store = IncidentStore()
    incident = store.get(incident_id)

    print(f"\n{'─'*60}")
    print("  INCIDENT REPLAY")
    print(f"{'─'*60}")
    for step in incident.replay():
        icon = {"success": "✓", "failed": "✗", "pending": "?"}.get(step["status"], "•")
        print(f"\n  Step {step['step']}: {icon}  {step['description']}")
        print(f"    Type:       {step['action_type']}")
        print(f"    Risk:       {step['risk_level']}")
        print(f"    Reasoning:  {step['reasoning'] or '(none)'}")
        br = step["blast"]
        print(f"    Blast:      {br['resources_touched']} resource(s) | "
              f"irreversible={br['irreversible']}")
        print(f"    Chain OK:   {step['chain_valid']}")

    print(f"\n{'─'*60}")
    print("  FULL BLAST RADIUS")
    print(f"{'─'*60}")
    br = incident.full_blast_radius()
    print(f"  Total actions:         {br['total_actions']}")
    print(f"  Systems affected:      {br['systems_affected']}")
    print(f"  Irreversible actions:  {len(br['irreversible_action_ids'])}")
    print(f"  Can fully roll back:   {br['can_fully_rollback']}")
    print(f"  Chain integrity:       {incident.chain_integrity}")
    print()

    # Resolve the incident
    store.resolve(
        incident_id,
        root_cause="Agent used wrong context variable for user_id in GDPR workflow",
        resolution="Restored user data from backup. Added user_id validation step before delete.",
    )
    print(f"✓  Incident {incident_id[:8]}... resolved.\n")


if __name__ == "__main__":
    asyncio.run(main())

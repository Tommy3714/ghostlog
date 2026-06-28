# 👻 GhostLog

**AI Agent Incident Response Platform**

When your AI agent makes a bad decision at 3am — deletes the wrong record, calls the wrong API, takes an irreversible action — what do you do?

Today: nothing. No replay. No blast radius. No rollback map. No playbook.

**GhostLog** gives every AI agent a tamper-proof decision log, incident replay, blast radius calculator, and alert system. Framework-agnostic. Zero required config. Drop it into any Python agent in minutes.

---

## The problem

> *"Who owns an agent when it fails at 3am? How do you do incident response when the failure mode is 'made a bad decision in an opaque way'?"*
> — [AI Agents in April 2026, DEV Community](https://dev.to)

Organizations are deploying AI agents faster than they can govern them. Every service account, every API key, every workflow accumulates actions nobody can audit after the fact.

GhostLog is the missing infrastructure layer.

---

## Features

- **Decision replay** — step-by-step why the agent chose what it chose, with full input/output at each step
- **Hash-chained audit trail** — every action links to the previous via SHA-256; tamper-evident by design
- **Blast radius calculator** — every system and resource touched, reversible vs. irreversible, per-action and per-incident
- **Irreversible action alerts** — fires the moment an agent takes a non-undoable action (webhook + console)
- **Incident declaration & resolution** — declare, replay, document root cause, mark resolved
- **REST API** — full FastAPI interface for dashboards, integrations, and alerting pipelines
- **Framework agnostic** — wraps any Python agent: LangChain, Claude Code, n8n, custom agents
- **Zero config start** — SQLite out of the box, Postgres-ready for production

---

## Quickstart

```bash
pip install ghostlog
```

```python
from ghostlog import GhostTracer, RiskLevel

tracer = GhostTracer(agent_id="my-agent")

# Decorator style
@tracer.trace(action_type="db_write", risk_level=RiskLevel.HIGH)
async def write_record(data: dict) -> dict:
    ...

# Context manager style — full control
async with tracer.action("Delete user record", risk_level=RiskLevel.CRITICAL) as ctx:
    ctx.touch("postgres", "users", "DELETE", reversible=False)
    ctx.record_reasoning("User requested GDPR deletion")
    result = await db.delete(user_id)
    ctx.record_output(result)

# Declare an incident from the current session
incident_id = tracer.declare_incident(
    title="Agent deleted wrong user",
    severity=RiskLevel.CRITICAL,
)
```

---

## Run the example

```bash
git clone https://github.com/YOUR_USERNAME/ghostlog
cd ghostlog
pip install -e ".[dev]"
python examples/basic_agent.py
```

---

## REST API

```bash
uvicorn ghostlog.api.main:app --reload
```

| Endpoint | Description |
|---|---|
| `GET /incidents` | All declared incidents |
| `GET /incidents/{id}/replay` | Step-by-step decision replay |
| `GET /incidents/{id}/blast-radius` | Full blast radius across all actions |
| `POST /incidents/{id}/resolve` | Resolve with root cause + resolution |
| `GET /actions/high-risk` | All high/critical actions across all agents |
| `GET /actions/{id}/blast-radius` | Single action blast radius |

Interactive docs: `http://localhost:8000/docs`

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `GHOSTLOG_DB` | `~/.ghostlog/ghostlog.db` | SQLite database path |
| `GHOSTLOG_WEBHOOK_URL` | *(none)* | Webhook URL for alerts |
| `GHOSTLOG_ALERT_EMAIL` | *(none)* | Email for critical alerts |

---

## Run tests

```bash
pytest tests/ -v
```

---

## Roadmap

- [ ] Postgres backend
- [ ] Rollback executor (auto-undo reversible actions)
- [ ] PagerDuty / Slack / OpsGenie integrations
- [ ] Web dashboard (React)
- [ ] OpenTelemetry export
- [ ] Multi-agent session tracking (A2A)
- [ ] LangChain / Claude Code native adapters

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT

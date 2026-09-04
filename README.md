# BLACKBOX

Adaptive Security & Forensic Intelligence for AI Agents & AI Automation — built for HackWave 3.0.

Blackbox is a security control layer around AI agents and AI-powered automation. It does not secure the model — it secures the agent's *behavior*: it observes what an agent does, detects dangerous behavior deterministically, reconstructs the attack path, explains *why* it happened (via Featherless), simulates and applies the minimum effective defense, then replays the attack to verify the fix actually holds.

> Deterministic systems establish security truth. LLMs explain that truth. An LLM is never the final authority on whether an event happened, whether a resource is reachable, blast radius, authorization, policy enforcement, or whether a defense worked.

## Architecture

```
Real AI Agent -> Blackbox SDK -> Event Collector -> Normalizer -> Universal AgentEvent
  -> Execution Graph -> {Detect, AEGIS, Evidence Extraction} -> Incident
  -> Understand Layer -> Featherless -> (root cause / narrative / critical decision / evidence)
  -> What-If -> Deterministic Simulation -> Intervention -> Apply Defense
  -> CHIMERA (re-attack) -> Verification -> Failure Pattern storage
```

| Layer | Path | Status |
|---|---|---|
| Universal AgentEvent schema | `backend/app/events/schemas.py` | **Implemented** |
| Event storage (append-only SQLite) | `backend/app/events/storage.py` | **Implemented** |
| Event collector + API | `backend/app/events/collector.py`, `backend/app/api/routes_events.py` | **Implemented** |
| Normalizer | `backend/app/events/normalizer.py` | Stub |
| Execution graph (NetworkX) | `backend/app/graph/builder.py` | Stub |
| Deterministic detection | `backend/app/detect/rules.py` | Stub |
| AEGIS / blast radius | `backend/app/aegis/blast_radius.py` | Stub |
| Evidence extraction | `backend/app/evidence/extractor.py` | Stub |
| Understand layer + Featherless | `backend/app/understand/` | Stub |
| What-if simulation | `backend/app/whatif/simulator.py` | Stub |
| Intervention engine | `backend/app/intervention/engine.py` | Stub |
| CHIMERA (re-attack) | `backend/app/chimera/replay.py` | Stub |
| Self-protection / Safe Mode | `backend/app/selfprotect/integrity.py` | Stub |
| Blackbox SDK / observer | `sdk/observer.py` | Stub |
| Test agent (target) | `agent/` | Placeholder |
| Frontend (React/TS/Vite/Tailwind) | `frontend/` | Scaffold only |

Stubs raise `NotImplementedError` — they mark the shape of the system, not working logic. See `DEVELOPMENT RULES` below before filling one in.

## Running the backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd backend
uvicorn app.main:app --reload
```

Then:

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/events -H "Content-Type: application/json" -d '{
  "event_id": "E1", "session_id": "S1", "agent_id": "A1",
  "event_type": "TOOL_CALL", "source": "agent",
  "resource": "customer_database", "trust_level": "UNTRUSTED"
}'
curl "http://127.0.0.1:8000/events?session_id=S1"
```

## Tests

```bash
cd backend
pytest tests -q
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `BLACKBOX_DB_PATH` | SQLite file for the event store | `blackbox.db` |
| `FEATHERLESS_API_KEY` | Featherless API key (never hardcode) | none |
| `FEATHERLESS_BASE_URL` | Featherless OpenAI-compatible base URL | `https://api.featherless.ai/v1` |
| `FEATHERLESS_MODEL` | Model name, configurable | `featherless/default` |

## Development rules

1. Work in small vertical slices, one module at a time.
2. Freeze contracts before implementing dependent modules — `AgentEvent` is frozen; treat schema changes as breaking.
3. Agent events are untrusted input — validate every event before analysis.
4. Keep deterministic security logic separate from LLM logic; the LLM explains, it never decides.
5. LLM output must be schema-validated (`backend/app/understand/investigation/schemas.py`).
6. Keep raw evidence separate from generated explanations.
7. Blackbox must not crash if Featherless is unavailable — fall back to deterministic templates.
8. No hardcoded secrets — everything Featherless-related comes from environment variables.

## Next modules

In spec order: execution graph builder -> deterministic detection rules -> AEGIS blast radius -> the real test agent + SDK wiring -> Understand/Featherless -> what-if/intervention/CHIMERA -> live frontend data wiring. Each gets implemented and tested on its own, per the rules above.

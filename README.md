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
| Agent event ingestion + storage | `backend/app/events/` | **Implemented** |
| P1.1 Execution graph (NetworkX) | `backend/app/graph/` | **Implemented** |
| P1.2 Deterministic detection | `backend/app/detection/` | **Implemented** |
| P1.3 AEGIS impact + blast radius | `backend/app/aegis/` | **Implemented** |
| P1 -> P2 contract (`IncidentAnalysis`) | `backend/app/contracts/incident_analysis.py`, `contracts/incident_analysis.json` | **Implemented** |
| P1.4 Orchestrator (`run_pipeline`) | `backend/app/orchestrator.py` | **Implemented** |
| P2 evidence extraction (IncidentAnalysis -> LLM-ready package) | `backend/app/understand/evidence/extractor.py` | **Implemented** |
| Featherless client (OpenAI-compatible) | `backend/app/understand/featherless/client.py` | **Implemented**, live-tested |
| Investigation schema + prompt | `backend/app/understand/investigation/schemas.py`, `prompts.py` | **Implemented** |
| Investigator orchestration (`investigate(incident)`) | `backend/app/understand/investigation/investigator.py` | **Implemented** |
| Deterministic fallback (Featherless unavailable) | `backend/app/understand/fallback/deterministic.py` | **Implemented** |
| `POST /investigate` API route | `backend/app/api/routes_investigate.py` | **Implemented**, live-tested |
| What-if simulation | `backend/app/whatif/simulator.py` | **Implemented** |
| Minimum-effective intervention | `backend/app/intervention/` | **Implemented** |
| CHIMERA re-attack + verification | `backend/app/chimera/replay.py` | **Implemented** |
| Self-protection / Safe Mode | `backend/app/selfprotect/integrity.py` | Stub |
| Blackbox SDK / observer | `sdk/observer.py` | Stub |
| Test agent (target) | `agent/` | Placeholder |
| Frontend (React/TS/Vite/Tailwind) | `frontend/` | Scaffold only |

Remaining stubs (`events/normalizer.py`, `evidence/extractor.py`, `selfprotect/integrity.py`, `understand/reasoning/recommendation.py`, `sdk/observer.py`) raise `NotImplementedError` — they mark shape, not working logic.

Run the full MVP loop: `app.orchestrator.run_pipeline(events, known_sensitive_resources=...)` — see `backend/app/scenarios/exfiltration.py` and `backend/tests/test_mvp_pipeline.py`.

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

curl -X POST http://127.0.0.1:8000/investigate -H "Content-Type: application/json" -d @- <<'JSON'
{
  "incident_id": "INC-1", "agent_id": "A1", "session_id": "S1",
  "incident_type": "INDIRECT_PROMPT_INJECTION", "severity": "CRITICAL",
  "events": [], "attack_path": [], "permissions": [],
  "sensitive_resources": [], "blast_radius": {}, "evidence": []
}
JSON
```

`POST /investigate` accepts a P1 `IncidentAnalysis` payload (see `contracts/incident_analysis.json`) and returns a structured `Investigation` via Featherless, falling back to the deterministic path if Featherless is unavailable. The route is a thin FastAPI translation layer over `app.understand.investigation.investigator.investigate()`, which has no FastAPI dependency and is tested independently of it.

## Tests

```bash
cd backend
pytest tests -q
```

The automated suite never calls the real Featherless API — `FeatherlessClient` is mocked in `tests/test_featherless_client.py`. To manually verify a real Featherless call end-to-end (requires `FEATHERLESS_API_KEY` and `FEATHERLESS_MODEL` set, e.g. via `.env`):

```bash
cd backend
python scripts/featherless_smoke_test.py
```

This script is not collected by pytest and never runs automatically.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Environment variables

Copy `.env.example` to `.env` (gitignored, never commit it) and fill in real values:

```bash
cp .env.example .env
```

| Variable | Purpose | Default |
|---|---|---|
| `BLACKBOX_DB_PATH` | SQLite file for the event store | `blackbox.db` |
| `FEATHERLESS_API_KEY` | Featherless API key (never hardcode) | none |
| `FEATHERLESS_BASE_URL` | Featherless OpenAI-compatible base URL | `https://api.featherless.ai/v1` |
| `FEATHERLESS_MODEL` | Model name, configurable | `NousResearch/Meta-Llama-3.1-8B-Instruct` |

## P1 -> P2 contract

`contracts/incident_analysis.json` is the language-agnostic JSON Schema for `IncidentAnalysis` — the security evidence P1 (execution graph + detection + AEGIS) hands to P2 (Understand/Featherless). The Pydantic source of truth is `backend/app/contracts/incident_analysis.py`; the JSON file is generated from it. It represents evidence P1 has already determined to be true, not raw application logs, and not something the LLM is asked to (re)discover.

## Development rules

1. Work in small vertical slices, one module at a time.
2. Freeze contracts before implementing dependent modules — `AgentEvent` is frozen; treat schema changes as breaking.
3. Agent events are untrusted input — validate every event before analysis.
4. Keep deterministic security logic separate from LLM logic; the LLM explains, it never decides.
5. LLM output must be schema-validated (`backend/app/understand/investigation/schemas.py`).
6. Keep raw evidence separate from generated explanations.
7. Blackbox must not crash if Featherless is unavailable — fall back to deterministic templates.
8. No hardcoded secrets — everything Featherless-related comes from environment variables.

## Person 2 (Understand/Featherless) — Definition of Done

- [x] P1 -> P2 contract is frozen (`contracts/incident_analysis.json`, `backend/app/contracts/incident_analysis.py`)
- [x] Evidence extractor works (`backend/app/understand/evidence/extractor.py`)
- [x] Security evidence package is generated deterministically (no LLM call in `build_prompt_evidence`)
- [x] Featherless configuration works (`.env` + `backend/app/core/config.py`)
- [x] Featherless client works (`backend/app/understand/featherless/client.py`)
- [x] Investigation schemas work (`backend/app/understand/investigation/schemas.py`)
- [x] Investigation prompts work (`backend/app/understand/investigation/prompts.py`)
- [x] Investigator pipeline works (`backend/app/understand/investigation/investigator.py`)
- [x] Deterministic fallback works (`backend/app/understand/fallback/deterministic.py`)
- [x] Featherless integration works with a real request (live-verified, see below)
- [x] BLACKBOX can consume the investigation result (`POST /investigate`)
- [x] Synthetic end-to-end investigation works (`backend/tests/test_end_to_end_demo.py`)
- [x] Featherless failure is handled (`backend/tests/test_failure_behavior.py`, condition B)
- [x] Malformed LLM output is handled safely (`backend/tests/test_failure_behavior.py`, condition D)
- [x] Automated tests pass (60/60, no network calls)
- [x] No secrets are committed (audited — see Security notes below)
- [x] P1 remains the source of security truth (Investigation carries no `attack_path`/`blast_radius`/`permissions`/`sensitive_resources`/`events` fields; nothing the LLM returns can overwrite a P1 fact)

Person 2's milestone is complete. Remaining Phase-2 work (execution graph, detection, AEGIS, real test agent + SDK, what-if/intervention, CHIMERA, self-protection, frontend data wiring) is explicitly out of scope here and picked up separately.

## Security notes

- The Featherless API key is only ever read via `os.environ`/`.env` (`backend/app/core/config.py`) — never hardcoded, never returned by an API response, never logged.
- `.env` is gitignored (verified at both repo root and nested paths); `.env.example` holds placeholders only.
- `backend/scripts/featherless_smoke_test.py` is a manual-only script, not collected by pytest — the automated suite (`pytest tests`) never depends on network access or a real key.

## Next modules

In spec order: execution graph builder -> deterministic detection rules -> AEGIS blast radius -> the real test agent + SDK wiring -> what-if/intervention/CHIMERA -> self-protection/Safe Mode -> live frontend data wiring. Each gets implemented and tested on its own, per the rules above.

# BLACKBOX Knowledge Base

This file did not exist before Person 2.2 (Investigation Layer Integration &
Evidence Hardening). It documents the finalized P2.2 architecture only —
the Understand/Featherless investigation layer. It does not cover P1
(execution graph, detection, AEGIS — still stubs), the frontend, or later
phases (Chimera, self-protection, etc.); those get their own sections here
when they're built, and this section should not be rewritten to describe
them speculatively in the meantime.

## P1 → P2 contract

`IncidentAnalysis` (`backend/app/contracts/incident_analysis.py`, mirrored
as language-agnostic JSON Schema at `contracts/incident_analysis.json`) is
the frozen contract P1 hands to P2. It represents **security evidence P1
has already determined to be true** — not raw application logs, and not
something P2 or an LLM is asked to (re)discover.

Fields: `incident_id`, `agent_id`, `session_id`, `incident_type`,
`severity`, `events` (list of `AgentEvent`), `attack_path`, `permissions`,
`sensitive_resources`, `blast_radius`, `evidence` (list of tagged
`EvidenceItem`).

**Immutability (Checkpoint 5):** `IncidentAnalysis` and its nested
`BlastRadius`/`PermissionFact`/`SensitiveResource` models are
`frozen=True` — attribute reassignment raises `ValidationError`.
`attack_path`, `permissions`, and `sensitive_resources` are `tuple`, not
`list`, so in-place mutation (`.append`, `__setitem__`) is impossible too.
`events`/`evidence` were deliberately left as mutable `list` — outside
this hardening's named scope (severity/attack_path/blast_radius/
permissions/sensitive_resources).

## Evidence provenance

`build_prompt_evidence()` (`backend/app/understand/evidence/extractor.py`)
deterministically compresses an `IncidentAnalysis` into a compact,
LLM-ready package — initial trigger, suspicious input, trust boundary
crossings, important decisions, tool calls, privilege changes, sensitive
resources accessed, data movement, external destinations, detection
findings, anomalies, attack path, blast radius. Pure filtering/grouping of
already-given facts; no LLM call, no inference.

`known_event_ids(evidence)` collects every legitimate `event_id` present
anywhere in that package. `FeatherlessClient._validate_provenance()` checks
every `event_id` a Featherless response references (`critical_decision`,
each `evidence_interpretation` entry) against this set — an unknown ID
raises `FeatherlessError` (caught by the Investigator, routed to the
deterministic fallback). This is what stops a hallucinated event_id from
being silently accepted as confirmed evidence.

## Fact vs. interpretation boundary

`Investigation` (`backend/app/understand/investigation/schemas.py`) —
`root_cause`, `attack_narrative`, `critical_decision`,
`evidence_interpretation`, `confidence`, `contributing_factors`,
`failure_pattern_candidate` — has **no field that could carry a P1 fact**
(`events`, `attack_path`, `permissions`, `sensitive_resources`,
`blast_radius` are all structurally absent). An LLM response literally
cannot overwrite or restate a P1 finding; there's nowhere for it to go.
`critical_decision`/`evidence_interpretation` are the only fields that cite
a specific `event_id` — provenance-checked, per above. `root_cause`/
`attack_narrative`/`contributing_factors` are plain `str`/`list[str]`, free
prose with no grounding claim to defend.

## Featherless's role

Interprets evidence; is never the security authority. Called only from
`backend/app/understand/featherless/client.py` (`FeatherlessClient`) —
verified by a static AST scan (`test_investigator_integration.py`) that no
other file under `app/understand/` imports `openai`. Uses the official
`openai` SDK against Featherless's OpenAI-compatible endpoint
(`FEATHERLESS_BASE_URL`, default `https://api.featherless.ai/v1`); model
is fully configurable via `FEATHERLESS_MODEL` (currently defaults to
`NousResearch/Meta-Llama-3.1-8B-Instruct`, verified working live).

The system prompt (`backend/app/understand/investigation/prompts.py`)
establishes the philosophy ("We don't secure the model. We secure the
agent's behavior." / "Technology changes. Failure patterns persist."), the
P1/P2 authority split, an explicit MUST list (use only supplied evidence,
explain why, reconstruct the attack chain, identify root cause and
critical decision, explain relationships between evidence, reference
supporting event_ids, distinguish fact from inference), and an explicit
MUST NOT list (invent events/event IDs/tools/permissions/resources/
timestamps/agents/attack paths; invent or restate evidence; modify or
contradict severity/blast_radius/any P1 finding; reference an event_id not
in the supplied evidence).

## Investigator

`investigate(incident, *, settings=None, client=None)`
(`backend/app/understand/investigation/investigator.py`) — the single
entry point: `IncidentAnalysis` → `build_prompt_evidence()` →
`FeatherlessClient.analyze()` → `Investigation`, catching `FeatherlessError`
specifically (not a broad `except Exception` — a real bug in an injected
client still propagates, verified by test) and falling back to
`fallback_investigation()` on it. Framework-agnostic: no FastAPI import
anywhere in `app/understand/` (verified by static AST scan, not just
absence-of-error-at-runtime, since `fastapi` is already loaded elsewhere in
the same test process by the time any test runs). `settings`/`client` are
optional injection points; `investigate(incident)` alone is the documented
simple interface.

`POST /investigate` (`backend/app/api/routes_investigate.py`) is a thin
2-line HTTP translation layer over this — validates the request body as
`IncidentAnalysis`, returns `Investigation`, contains no investigation
logic of its own, never touches Settings/the API key directly.

## Deterministic fallback

`fallback_investigation(evidence)`
(`backend/app/understand/fallback/deterministic.py`) — runs whenever
`investigate()` catches a `FeatherlessError`, for any reason: missing/
invalid API key, timeout, connection failure, authentication failure, rate
limit, malformed (invalid JSON or schema-invalid) response, or a
provenance violation. No LLM reasoning happens here.

`root_cause`/`attack_narrative` are rendered as three explicitly labeled
sections:

```
CONFIRMED:
<facts stated plainly, e.g. "Agent accessed confirmed sensitive resource(s): customer_database.">

DETERMINISTIC INFERENCE:
<a small number of fixed rules applied to those facts, e.g. "Sensitive data reached an external destination.">

AI EXPLANATION:
Unavailable -- Featherless could not be reached. This is a deterministic-only report...
```

`confidence` is always `0.0` — signaling "no AI assessment was made," not
"zero confidence in the underlying facts." `failure_pattern_candidate` is
always `None` — abstracting a reusable pattern requires generalization the
fallback deliberately doesn't attempt. `critical_decision` picks the first
`DECISION` event in the attack path by a fixed rule (or the honest
`"UNKNOWN"` sentinel if none exists), explicitly labeled "Deterministic
inference," never presented as an AI judgement.

## Malformed output handling

`FeatherlessClient.analyze()` rejects, rather than trusts, every malformed
shape:

| Failure mode | Where it's caught |
|---|---|
| Invalid JSON | `json.loads` → `FeatherlessError` |
| Missing required fields | `Investigation.model_validate` → `ValidationError` → `FeatherlessError` |
| Invalid confidence (outside [0, 1]) | `confidence: float = Field(ge=0.0, le=1.0)` → `ValidationError` → `FeatherlessError` |
| Nonexistent/fabricated event_id | `_validate_provenance()` → `FeatherlessError` |
| Wrong types (e.g. `critical_decision` as a string) | Pydantic type coercion failure → `ValidationError` → `FeatherlessError` |
| Contradictory prose claims (e.g. "severity is actually LOW") | Not rejected — harmless, since there's no field for it to land in; P1 facts are untouched regardless |

Every rejection path converges on the same `FeatherlessError` → deterministic
fallback route. Nothing malformed is ever returned to a caller as a trusted
`Investigation`.

## Security invariants

- Featherless API key: read only via `os.environ`/`.env`
  (`backend/app/core/config.py`), never hardcoded, never logged, never
  returned by any API response, never present in tests/fixtures/README
  (all use placeholder values like `"test-key"`), never in an exception
  message (tested explicitly). `.env` is gitignored (verified at root and
  nested paths); `.env.example` holds placeholders only. Verified clean
  across the full `git log --all -p` history, not just the working diff.
- An LLM response cannot modify P1 security truth: structurally (no field
  exists for it), by immutability (frozen contract, tuples not lists), and
  by pipeline behavior (`investigate()` never writes back to `incident`) —
  all independently tested, including with deliberately contradictory LLM
  prose.
- The automated test suite (`pytest tests`, 150 tests as of this writing)
  makes zero live network calls — every `FeatherlessClient` in a test is
  either monkeypatched or never reaches the network. The one live-hitting
  artifact, `backend/scripts/featherless_smoke_test.py`, lives outside
  `tests/` and contributes zero collected test items even under a bare
  `pytest` run with no path argument.

## Current limitations

- P1 (`app/graph`, `app/detect`, `app/aegis`, `app/evidence`) is still all
  `NotImplementedError` stubs — everything above is proven against the
  synthetic `make_incident()`/`make_rich_incident()` fixtures, not a real
  detection pipeline yet.
- The deterministic fallback's `evidence_interpretation` only surfaces
  `trust_boundary_crossings` and `external_destinations` — it doesn't yet
  narrate `tool_calls`, `data_movement`, or `detection_findings`
  specifically (they're still preserved and forwarded to Featherless when
  it *is* available; only the fallback's own summary is partial).
- `openai.RateLimitError` has no dedicated unit test (the code path is
  structurally identical to the already-tested `AuthenticationError`
  branch, both `APIStatusError` subclasses).
- No retry-before-fallback: a single transient bad response from
  Featherless goes straight to the deterministic path rather than getting
  one more attempt at a real AI explanation.

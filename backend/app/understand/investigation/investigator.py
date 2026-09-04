"""Investigator — orchestrates the full P1 -> P2 pipeline:

    IncidentAnalysis -> evidence extractor -> structured evidence
    -> investigation prompt -> FeatherlessClient -> Investigation

Framework-agnostic: nothing here imports FastAPI or any web framework.
Callers (an API route, a CLI, a test) just call investigate(incident).

Falls back to app.understand.fallback.deterministic whenever Featherless is
unavailable -- missing/invalid API key, network failure, timeout, or a
response that fails schema validation -- so Blackbox never crashes just
because the LLM is unreachable.
"""

from __future__ import annotations

from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.core.config import Settings, get_settings
from backend.app.understand.evidence.extractor import build_prompt_evidence
from backend.app.understand.fallback.deterministic import fallback_investigation
from backend.app.understand.featherless.client import FeatherlessClient, FeatherlessError
from backend.app.understand.investigation.schemas import Investigation


def investigate(
    incident: IncidentAnalysis,
    *,
    settings: Settings | None = None,
    client: FeatherlessClient | None = None,
) -> Investigation:
    """Run one incident through the P1 -> P2 pipeline. `settings` and
    `client` are optional injection points for tests; normal callers just
    pass `incident`."""

    settings = settings or get_settings()
    evidence = build_prompt_evidence(incident)

    try:
        featherless = client or FeatherlessClient(settings)
        return featherless.analyze(evidence)
    except FeatherlessError:
        return fallback_investigation(evidence)

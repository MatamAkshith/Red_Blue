"""Phase 12 — end-to-end demonstration of the full P1 -> P2 pipeline on one
deterministic synthetic incident:

    Malicious document -> RAG retrieval -> indirect prompt injection
    -> agent decision -> CRM access -> sensitive data -> external email

This is test data only -- it does not depend on a real target agent.
Featherless is mocked (deterministic, no network call; see
tests/test_featherless_client.py for API-mocking coverage and
scripts/featherless_smoke_test.py for the manual live check) so this test
demonstrates the pipeline wiring itself, not Featherless's language
quality.
"""

from __future__ import annotations

import json

from app.core.config import Settings
from app.contracts.incident_analysis import IncidentAnalysis
from app.understand.evidence.extractor import build_prompt_evidence
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import Investigation
from tests.test_contracts import make_incident
from tests.test_featherless_client import VALID_INVESTIGATION


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


class _RecordingFeatherlessClient:
    """Stands in for FeatherlessClient: returns a fixed, valid Investigation
    and records exactly what evidence it was handed, so the test can assert
    on the Investigator -> Featherless boundary without a network call."""

    def __init__(self):
        self.received_evidence = None

    def analyze(self, evidence):
        self.received_evidence = evidence
        return Investigation.model_validate(json.loads(json.dumps(VALID_INVESTIGATION)))


def test_full_pipeline_demonstrates_each_stage():
    # 1. P1 provides security evidence -- the deterministic engine has
    #    already established these as fact (event types, trust levels,
    #    attack path, permissions, sensitive resources, blast radius).
    incident: IncidentAnalysis = make_incident()
    assert incident.incident_type == "INDIRECT_PROMPT_INJECTION"
    assert incident.attack_path == ["E14", "E15", "E16", "E17"]
    assert incident.blast_radius.risk_score == 8.5

    # 2. Evidence Extractor compresses IncidentAnalysis into a compact,
    #    LLM-ready investigation evidence package -- still pure fact, no
    #    interpretation yet.
    evidence = build_prompt_evidence(incident)
    assert evidence["incident_id"] == incident.incident_id
    assert evidence["attack_path"] == incident.attack_path
    assert evidence["initial_trigger"]["event_id"] == "E14"
    assert [e["event_id"] for e in evidence["tool_calls"]] == ["E16"]

    # 3 & 4. Investigator sends that evidence to Featherless, which explains
    #    WHY the incident occurred. Here Featherless is a recording double
    #    so the test stays deterministic and network-free.
    fake_client = _RecordingFeatherlessClient()
    result = investigate(incident, settings=make_settings(), client=fake_client)

    assert fake_client.received_evidence == evidence

    # 5. BLACKBOX receives a structured InvestigationResult.
    assert isinstance(result, Investigation)
    assert result.root_cause
    assert result.attack_narrative
    assert result.critical_decision.event_id in {e.event_id for e in incident.events}

    # 6. The result clearly separates evidence (facts P1 already
    #    established, still reachable on `incident`/`evidence`) from AI
    #    interpretation (`result`, which only ever references those facts
    #    by event_id -- it carries no attack_path, blast_radius, or
    #    permissions fields of its own to contradict P1's).
    assert not hasattr(result, "attack_path")
    assert not hasattr(result, "blast_radius")
    assert not hasattr(result, "permissions")
    for item in result.evidence_interpretation:
        assert item.event_id in {e.event_id for e in incident.events}

    # P1's facts are untouched by having gone through the LLM.
    assert incident.attack_path == ["E14", "E15", "E16", "E17"]
    assert incident.blast_radius.risk_score == 8.5

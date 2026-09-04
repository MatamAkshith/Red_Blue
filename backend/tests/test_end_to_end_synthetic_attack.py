"""Checkpoint 11 -- end-to-end synthetic attack, using the named controlled
scenario:

    Malicious Document -> RAG Retrieval -> Indirect Prompt Injection
    -> Agent Decision -> CRM Tool -> Customer Database -> External Request

(This is exactly the make_incident() fixture: E14 retrieval of a malicious
document, E15 the agent's decision, E16 the CRM tool call reaching
customer_database, E17 the external action.)

Deterministic/mocked here per the no-live-calls-in-automated-tests rule;
see scripts/featherless_smoke_test.py, and this session's live runs
recorded in the checkpoint reports, for the live-Featherless leg of this
same scenario.
"""

from __future__ import annotations

import json

from backend.app.understand.evidence.extractor import build_prompt_evidence, known_event_ids
from backend.app.understand.featherless.client import FeatherlessClient
from backend.app.understand.investigation.investigator import investigate
from backend.app.core.config import Settings
from tests.test_contracts import make_incident
from tests.test_featherless_client import fake_completion


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def _plausible_investigation_payload() -> dict:
    # Mirrors what real Featherless runs against this exact incident
    # produced live during this session's Checkpoint 4/6/10 verification.
    return {
        "root_cause": "Untrusted retrieval of a malicious document influenced the "
        "agent's decision to access a sensitive resource.",
        "attack_narrative": "The agent retrieved a malicious document (E14), which "
        "influenced its decision (E15) to call the CRM tool (E16) against "
        "customer_database, then attempt an external transmission (E17).",
        "critical_decision": {
            "event_id": "E15",
            "explanation": "The agent treated untrusted retrieved content as an "
            "actionable instruction to access the CRM.",
        },
        "evidence_interpretation": [
            {"event_id": "E14", "interpretation": "Untrusted retrieval source"},
            {"event_id": "E16", "interpretation": "Privileged CRM tool call reached a sensitive resource"},
            {"event_id": "E17", "interpretation": "Attempted external data transmission"},
        ],
        "confidence": 0.95,
        "contributing_factors": ["No sanitization of retrieved content before the decision step"],
        "failure_pattern_candidate": {
            "pattern_name": "untrusted_retrieval_to_privileged_tool",
            "description": "Untrusted retrieved content reaches a privileged tool call",
            "indicators": ["RETRIEVAL(untrusted) -> DECISION -> TOOL_CALL(privileged)"],
        },
    }


def test_synthetic_attack_pipeline_produces_a_complete_grounded_investigation(monkeypatch):
    incident = make_incident()
    real_event_ids = {e.event_id for e in incident.events}
    assert real_event_ids == {"E14", "E15", "E16", "E17"}

    evidence = build_prompt_evidence(incident)
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(_plausible_investigation_payload())),
    )

    result = investigate(incident, settings=make_settings(), client=client)

    # root cause
    assert result.root_cause
    # attack narrative
    assert result.attack_narrative
    # critical decision -- correctly identifies the DECISION event
    assert result.critical_decision.event_id == "E15"
    # evidence interpretation / supporting evidence references
    assert result.evidence_interpretation
    referenced_ids = {result.critical_decision.event_id} | {
        item.event_id for item in result.evidence_interpretation
    }

    # every referenced event ID actually exists in the real incident
    assert referenced_ids <= real_event_ids
    # ... and specifically within what P1 supplied as evidence, not just
    # "some real-looking string" -- the provenance check already enforced
    # this at analyze()-time, this re-derives it independently
    assert referenced_ids <= known_event_ids(evidence)

    # the LLM did not invent security facts: nothing on `incident` changed,
    # and nothing on `result` claims to *be* a P1 fact (no such field exists)
    assert incident.attack_path == ("E14", "E15", "E16", "E17")
    assert not hasattr(result, "attack_path")
    assert not hasattr(result, "blast_radius")
    assert not hasattr(result, "severity")


def test_synthetic_attack_scenario_matches_the_named_checkpoint_scenario():
    # Malicious Document -> RAG Retrieval -> Indirect Prompt Injection
    # -> Agent Decision -> CRM Tool -> Customer Database -> External Request
    incident = make_incident()
    events_by_id = {e.event_id: e for e in incident.events}

    assert events_by_id["E14"].event_type.value == "RETRIEVAL"
    assert events_by_id["E14"].resource == "malicious_document"
    assert events_by_id["E14"].trust_level.value == "UNTRUSTED"

    assert events_by_id["E15"].event_type.value == "DECISION"

    assert events_by_id["E16"].event_type.value == "TOOL_CALL"
    assert events_by_id["E16"].target == "crm"
    assert events_by_id["E16"].resource == "customer_database"

    assert events_by_id["E17"].event_type.value == "ACTION"
    assert events_by_id["E17"].target == "email"

    assert incident.attack_path == ("E14", "E15", "E16", "E17")

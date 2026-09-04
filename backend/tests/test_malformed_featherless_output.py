"""Checkpoint 8 -- malformed Featherless output. Every named failure mode
must be rejected (never treated as trusted security truth), and where
appropriate the pipeline must safely fall back rather than error out, with
P1 facts on the incident always left untouched.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.understand.evidence.extractor import build_prompt_evidence
from app.understand.featherless.client import FeatherlessClient, FeatherlessError
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import CriticalDecision, Investigation
from tests.test_contracts import make_incident
from tests.test_featherless_client import fake_completion


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def _client_with_response(content: str) -> FeatherlessClient:
    client = FeatherlessClient(make_settings())
    client._client.chat.completions.create = lambda **kwargs: fake_completion(content)
    return client


def _valid_payload(**overrides) -> dict:
    payload = {
        "root_cause": "x",
        "attack_narrative": "y",
        "critical_decision": {"event_id": "E15", "explanation": "z"},
        "evidence_interpretation": [],
        "confidence": 0.9,
        "contributing_factors": [],
        "failure_pattern_candidate": None,
    }
    payload.update(overrides)
    return payload


# 1. Invalid JSON ----------------------------------------------------------


def test_invalid_json_is_rejected_not_trusted():
    client = _client_with_response("this is not json { at all")
    with pytest.raises(FeatherlessError, match="not valid JSON"):
        client.analyze({})


def test_invalid_json_falls_back_safely_through_investigator():
    incident = make_incident()
    client = _client_with_response("this is not json { at all")
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0  # fallback, not trusted as real output


# 2. Missing fields ----------------------------------------------------------


def test_missing_fields_is_rejected_not_trusted():
    client = _client_with_response(json.dumps({"root_cause": "x"}))  # everything else missing
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


# 3. Invalid confidence --------------------------------------------------


def test_confidence_above_one_rejected_at_schema_level():
    with pytest.raises(ValidationError):
        Investigation(
            root_cause="x", attack_narrative="y",
            critical_decision=CriticalDecision(event_id="E1", explanation="z"),
            confidence=150.0,
        )


def test_confidence_below_zero_rejected_at_schema_level():
    with pytest.raises(ValidationError):
        Investigation(
            root_cause="x", attack_narrative="y",
            critical_decision=CriticalDecision(event_id="E1", explanation="z"),
            confidence=-5.0,
        )


def test_out_of_range_confidence_from_featherless_is_rejected_not_trusted():
    client = _client_with_response(json.dumps(_valid_payload(confidence=99.0)))
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_out_of_range_confidence_falls_back_safely_through_investigator():
    incident = make_incident()
    client = _client_with_response(json.dumps(_valid_payload(confidence=99.0)))
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0


# 4. Nonexistent evidence IDs ----------------------------------------------


def test_nonexistent_evidence_id_is_rejected_not_trusted():
    evidence = build_prompt_evidence(make_incident())
    client = _client_with_response(json.dumps(_valid_payload(critical_decision={
        "event_id": "E_DOES_NOT_EXIST", "explanation": "z",
    })))
    with pytest.raises(FeatherlessError, match="fabricated or hallucinated"):
        client.analyze(evidence)


def test_nonexistent_evidence_id_falls_back_safely_through_investigator():
    incident = make_incident()
    evidence_client = _client_with_response(json.dumps(_valid_payload(critical_decision={
        "event_id": "E_DOES_NOT_EXIST", "explanation": "z",
    })))
    result = investigate(incident, settings=make_settings(), client=evidence_client)
    assert result.confidence == 0.0


# 5. Unsupported values (wrong type) ---------------------------------------


def test_wrong_type_for_confidence_is_rejected():
    client = _client_with_response(json.dumps(_valid_payload(confidence="very confident")))
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_wrong_type_for_critical_decision_is_rejected():
    client = _client_with_response(json.dumps(_valid_payload(critical_decision="E15")))
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_wrong_type_for_evidence_interpretation_is_rejected():
    client = _client_with_response(
        json.dumps(_valid_payload(evidence_interpretation="E14, E15"))
    )
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


# 6. Contradictory security claims -----------------------------------------


def test_contradictory_security_claim_does_not_alter_p1_facts(monkeypatch):
    incident = make_incident()
    original_severity = incident.severity
    original_blast_radius = incident.blast_radius

    # The payload is schema-valid -- the "contradiction" is only in prose,
    # since Investigation has no field that could actually carry a P1 fact.
    payload = _valid_payload(
        root_cause="Severity is actually LOW, not CRITICAL as claimed",
        attack_narrative="Blast radius is zero; nothing sensitive was reached",
    )
    client = _client_with_response(json.dumps(payload))
    investigate(incident, settings=make_settings(), client=client)

    assert incident.severity == original_severity
    assert incident.blast_radius == original_blast_radius


# 7. Malformed structure ----------------------------------------------------


def test_evidence_interpretation_items_missing_required_field_rejected():
    client = _client_with_response(
        json.dumps(_valid_payload(evidence_interpretation=[{"event_id": "E14"}]))  # no interpretation
    )
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_completely_empty_object_is_rejected():
    client = _client_with_response("{}")
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_json_array_instead_of_object_is_rejected():
    client = _client_with_response(json.dumps([_valid_payload()]))
    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


# --- blanket guarantee: every malformed mode preserves P1 facts ----------


@pytest.mark.parametrize(
    "bad_content",
    [
        "not json",
        "{}",
        json.dumps({"root_cause": "x"}),
        json.dumps(_valid_payload(confidence=99.0)),
        json.dumps(_valid_payload(critical_decision={"event_id": "FAKE", "explanation": "z"})),
    ],
)
def test_every_malformed_mode_preserves_p1_facts_via_fallback(bad_content):
    incident = make_incident()
    original_attack_path = incident.attack_path
    original_sensitive_resources = incident.sensitive_resources

    client = _client_with_response(bad_content)
    result = investigate(incident, settings=make_settings(), client=client)

    assert result.confidence == 0.0
    assert incident.attack_path == original_attack_path
    assert incident.sensitive_resources == original_sensitive_resources

"""Checkpoint 2 -- evidence provenance. Every investigation conclusion must
be traceable to real P1 evidence; fabricated/hallucinated event_ids must be
rejected, not silently accepted as confirmed evidence.
"""

from __future__ import annotations

import json

import pytest

from app.core.config import Settings
from app.understand.evidence.extractor import build_prompt_evidence, known_event_ids
from app.understand.featherless.client import FeatherlessClient, FeatherlessError
from tests.test_contracts import make_incident
from tests.test_featherless_client import fake_completion


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def investigation_payload(critical_event_id: str, evidence_event_ids: list[str]) -> dict:
    return {
        "root_cause": "test root cause",
        "attack_narrative": "test narrative",
        "critical_decision": {"event_id": critical_event_id, "explanation": "test"},
        "evidence_interpretation": [
            {"event_id": eid, "interpretation": "test"} for eid in evidence_event_ids
        ],
        "confidence": 0.8,
        "contributing_factors": [],
        "failure_pattern_candidate": None,
    }


# --- known_event_ids() unit coverage -----------------------------------


def test_known_event_ids_collects_from_every_bearing_bucket():
    evidence = build_prompt_evidence(make_incident())
    ids = known_event_ids(evidence)
    # E14..E17 are the full synthetic attack (retrieval, decision, tool
    # call, action) -- all four must be recognized as legitimate.
    assert ids == {"E14", "E15", "E16", "E17"}


def test_known_event_ids_handles_empty_evidence():
    assert known_event_ids({}) == set()


def test_known_event_ids_ignores_sensitive_resources_bucket():
    # SensitiveResource has no event_id field -- must not contribute one.
    evidence = {"sensitive_resources_accessed": [{"resource": "customer_database"}]}
    assert known_event_ids(evidence) == set()


# --- FeatherlessClient provenance enforcement ---------------------------


def test_valid_evidence_references_are_accepted(monkeypatch):
    client = FeatherlessClient(make_settings())
    evidence = build_prompt_evidence(make_incident())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(
            json.dumps(investigation_payload("E15", ["E14", "E16"]))
        ),
    )

    result = client.analyze(evidence)
    assert result.critical_decision.event_id == "E15"


def test_nonexistent_evidence_id_in_critical_decision_is_rejected(monkeypatch):
    client = FeatherlessClient(make_settings())
    evidence = build_prompt_evidence(make_incident())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(investigation_payload("E999", []))),
    )

    with pytest.raises(FeatherlessError, match="E999"):
        client.analyze(evidence)


def test_fabricated_event_id_in_evidence_interpretation_is_rejected(monkeypatch):
    client = FeatherlessClient(make_settings())
    evidence = build_prompt_evidence(make_incident())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(
            json.dumps(investigation_payload("E15", ["E14", "FABRICATED_ID"]))
        ),
    )

    with pytest.raises(FeatherlessError, match="FABRICATED_ID"):
        client.analyze(evidence)


def test_duplicate_evidence_references_are_accepted(monkeypatch):
    # Citing the same real event_id twice isn't fabrication -- it's
    # redundant, not dishonest. Must not be rejected.
    client = FeatherlessClient(make_settings())
    evidence = build_prompt_evidence(make_incident())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(
            json.dumps(investigation_payload("E15", ["E14", "E14"]))
        ),
    )

    result = client.analyze(evidence)
    assert [item.event_id for item in result.evidence_interpretation] == ["E14", "E14"]


def test_multiple_evidence_references_all_validated(monkeypatch):
    client = FeatherlessClient(make_settings())
    evidence = build_prompt_evidence(make_incident())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(
            json.dumps(investigation_payload("E15", ["E14", "E16", "E17"]))
        ),
    )

    result = client.analyze(evidence)
    assert len(result.evidence_interpretation) == 3


def test_empty_evidence_interpretation_is_valid(monkeypatch):
    # No evidence_interpretation entries at all (e.g. "insufficient
    # evidence" case) must not be treated as a provenance violation.
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(investigation_payload("E15", []))),
    )

    evidence = build_prompt_evidence(make_incident())
    result = client.analyze(evidence)
    assert result.evidence_interpretation == []

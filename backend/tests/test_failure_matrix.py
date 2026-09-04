"""Checkpoint 12 -- complete failure matrix A-J. Each case gets its own
named test so the matrix is directly traceable to the checkpoint spec,
even where the underlying behavior is already covered elsewhere (Checkpoints
2, 5, 7, 8, 10). Consolidating them here is the deliverable itself.
"""

from __future__ import annotations

import json

import httpx2
import openai
import pytest

from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.core.config import Settings
from backend.app.understand.featherless.client import FeatherlessClient
from backend.app.understand.investigation.investigator import investigate
from tests.test_contracts import make_incident
from tests.test_featherless_client import VALID_INVESTIGATION, fake_completion


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def _request() -> httpx2.Request:
    return httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")


# A. Featherless available -> AI investigation ----------------------------


def test_a_featherless_available_yields_ai_investigation(monkeypatch):
    incident = make_incident()
    evidence_with_real_ids = {
        "attack_path": ["E14", "E15"],
        "important_decisions": [{"event_id": "E15"}],
        "trust_boundary_crossings": [{"event_id": "E14"}],
    }
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(VALID_INVESTIGATION)),
    )
    result = client.analyze(evidence_with_real_ids)
    assert result.confidence == 0.9  # a real AI-produced value, not the fallback's 0.0


# B. Featherless unavailable -> deterministic fallback --------------------


def test_b_featherless_unavailable_yields_deterministic_fallback():
    result = investigate(make_incident(), settings=make_settings(api_key=None))
    assert result.confidence == 0.0
    assert "AI EXPLANATION:\nUnavailable" in result.root_cause


# C. Invalid incident -> validation failure --------------------------------


def test_c_invalid_incident_yields_validation_failure():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        IncidentAnalysis(agent_id="A1")  # missing required fields


# D. Invalid JSON -> safe rejection/fallback -------------------------------


def test_d_invalid_json_yields_safe_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion("{not json")
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0


# E. Missing investigation fields -> safe rejection/fallback --------------


def test_e_missing_fields_yields_safe_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps({"root_cause": "x"})),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0


# F. Invalid confidence -> safe rejection ----------------------------------


def test_f_invalid_confidence_yields_safe_rejection(monkeypatch):
    incident = make_incident()
    payload = {**VALID_INVESTIGATION, "confidence": 42.0}
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion(json.dumps(payload))
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0  # rejected by schema bounds, fell back safely


# G. Fake evidence ID -> rejection -----------------------------------------


def test_g_fake_evidence_id_yields_rejection(monkeypatch):
    incident = make_incident()
    payload = {**VALID_INVESTIGATION, "critical_decision": {"event_id": "TOTALLY_FAKE", "explanation": "z"}}
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion(json.dumps(payload))
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0  # provenance check rejected it, fell back safely


# H. Contradictory LLM security claim -> P1 facts remain unchanged --------


def test_h_contradictory_claim_leaves_p1_facts_unchanged(monkeypatch):
    incident = make_incident()
    original_severity = incident.severity
    original_blast_radius = incident.blast_radius

    payload = {
        **VALID_INVESTIGATION,
        "root_cause": "Severity is actually LOW and blast radius is zero",
    }
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion(json.dumps(payload))
    )
    investigate(incident, settings=make_settings(), client=client)

    assert incident.severity == original_severity
    assert incident.blast_radius == original_blast_radius


# I. Timeout -> safe fallback ------------------------------------------------


def test_i_timeout_yields_safe_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: (_ for _ in ()).throw(openai.APITimeoutError(request=_request())),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0


# J. Authentication failure -> safe fallback ---------------------------------


def test_j_authentication_failure_yields_safe_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    response = httpx2.Response(401, request=_request())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: (_ for _ in ()).throw(
            openai.AuthenticationError("bad key", response=response, body=None)
        ),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    assert result.confidence == 0.0

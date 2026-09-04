"""Phase 13 — failure behavior. Four conditions BLACKBOX must handle
without ever treating unverified model output as security truth, and
without ever crashing just because Featherless is unavailable. Fully
mocked; no network call.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.contracts.incident_analysis import IncidentAnalysis
from app.core.config import Settings
from app.main import app
from app.understand.featherless.client import FeatherlessClient, FeatherlessError
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import Investigation
from tests.test_contracts import make_incident
from tests.test_featherless_client import VALID_INVESTIGATION, fake_completion

client = TestClient(app)


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


# A. Featherless available -> AI investigation succeeds.
def test_a_featherless_available_ai_investigation_succeeds(monkeypatch):
    featherless_client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        featherless_client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(VALID_INVESTIGATION)),
    )

    result = investigate(make_incident(), settings=make_settings(), client=featherless_client)

    assert isinstance(result, Investigation)
    assert result.confidence == 0.9  # a real, non-fallback confidence value
    assert result.root_cause


# B. Featherless unavailable -> deterministic fallback succeeds.
def test_b_featherless_unavailable_fallback_succeeds():
    result = investigate(make_incident(), settings=make_settings(api_key=None))

    assert isinstance(result, Investigation)
    assert result.confidence == 0.0
    assert "AI explanation unavailable" in result.root_cause


# C. Invalid/malformed incident -> validation failure is returned cleanly.
def test_c_malformed_incident_rejected_at_the_model_boundary():
    with pytest.raises(ValidationError):
        IncidentAnalysis(agent_id="A1")  # missing incident_id, session_id, ...


def test_c_malformed_incident_rejected_cleanly_by_the_api():
    resp = client.post("/investigate", json={"agent_id": "A1"})

    assert resp.status_code == 422
    # a clean 4xx, not a 500 -- the app never crashes on bad input
    assert resp.json()["detail"]


# D. Featherless returns malformed output -> BLACKBOX must reject/handle it
# safely rather than treating the model output as security truth.
def test_d_non_json_model_output_is_rejected_not_trusted(monkeypatch):
    featherless_client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        featherless_client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion("Sure! Here is my analysis: it looks bad."),
    )

    with pytest.raises(FeatherlessError, match="not valid JSON"):
        featherless_client.analyze({})


def test_d_schema_invalid_model_output_is_rejected_not_trusted(monkeypatch):
    featherless_client = FeatherlessClient(make_settings())
    # Valid JSON, but missing required fields (e.g. critical_decision) --
    # must not be silently accepted as a valid Investigation.
    monkeypatch.setattr(
        featherless_client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps({"root_cause": "looks bad"})),
    )

    with pytest.raises(FeatherlessError, match="schema validation"):
        featherless_client.analyze({})


def test_d_malformed_output_falls_back_instead_of_propagating_bad_data():
    class _MalformedClient:
        def analyze(self, evidence):
            raise FeatherlessError("Featherless response failed schema validation")

    result = investigate(make_incident(), settings=make_settings(), client=_MalformedClient())

    assert isinstance(result, Investigation)
    assert result.confidence == 0.0  # the safe deterministic result, not model output


# LLM output cannot modify deterministic security facts.
def test_llm_output_cannot_modify_deterministic_facts():
    incident = make_incident()
    original_attack_path = list(incident.attack_path)
    original_risk_score = incident.blast_radius.risk_score
    original_sensitive = [r.resource for r in incident.sensitive_resources]

    class _FakeClient:
        def analyze(self, evidence):
            return Investigation.model_validate(VALID_INVESTIGATION)

    investigate(incident, settings=make_settings(), client=_FakeClient())

    # The Investigation schema has no field that can overwrite P1 facts,
    # and the incident object itself is never mutated by investigate().
    assert incident.attack_path == original_attack_path
    assert incident.blast_radius.risk_score == original_risk_score
    assert [r.resource for r in incident.sensitive_resources] == original_sensitive
    assert not set(Investigation.model_fields) & {
        "attack_path",
        "blast_radius",
        "permissions",
        "sensitive_resources",
        "events",
    }

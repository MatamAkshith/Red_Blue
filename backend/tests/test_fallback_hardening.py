"""Checkpoint 7 -- deterministic fallback hardening. Proves the fallback
produces a clearly-labeled CONFIRMED / DETERMINISTIC INFERENCE / AI
EXPLANATION report under every named failure condition, and that it never
fabricates AI reasoning or claims an LLM explanation exists.
"""

from __future__ import annotations

import httpx2
import openai
import pytest

from backend.app.core.config import Settings
from backend.app.understand.evidence.extractor import build_prompt_evidence
from backend.app.understand.featherless.client import FeatherlessClient
from backend.app.understand.fallback.deterministic import fallback_investigation
from backend.app.understand.investigation.investigator import investigate
from tests.test_contracts import make_incident


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def _assert_well_formed_fallback_report(result, incident) -> None:
    for text in (result.root_cause, result.attack_narrative):
        assert "CONFIRMED:" in text
        assert "DETERMINISTIC INFERENCE:" in text
        # the literal "Unavailable" marker -- never a fabricated explanation
        assert "AI EXPLANATION:\nUnavailable" in text
    assert result.confidence == 0.0
    assert result.failure_pattern_candidate is None
    # P1 facts on the incident itself are untouched regardless of failure mode
    assert incident.severity == make_incident().severity
    assert incident.attack_path == make_incident().attack_path


def _request() -> httpx2.Request:
    return httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")


# A. API / Featherless unavailable (no key configured at all) -----------


def test_api_unavailable_via_missing_key_produces_well_formed_fallback():
    incident = make_incident()
    result = investigate(incident, settings=make_settings(api_key=None))
    _assert_well_formed_fallback_report(result, incident)


# B. Timeout --------------------------------------------------------------


def test_timeout_produces_well_formed_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: (_ for _ in ()).throw(openai.APITimeoutError(request=_request())),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    _assert_well_formed_fallback_report(result, incident)


# C. Authentication failure -----------------------------------------------


def test_authentication_failure_produces_well_formed_fallback(monkeypatch):
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
    _assert_well_formed_fallback_report(result, incident)


# D. Connection failure -----------------------------------------------------


def test_connection_failure_produces_well_formed_fallback(monkeypatch):
    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: (_ for _ in ()).throw(openai.APIConnectionError(request=_request())),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    _assert_well_formed_fallback_report(result, incident)


# E. Malformed response (invalid JSON) -------------------------------------


def test_malformed_json_response_produces_well_formed_fallback(monkeypatch):
    from tests.test_featherless_client import fake_completion

    incident = make_incident()
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion("not valid json at all"),
    )
    result = investigate(incident, settings=make_settings(), client=client)
    _assert_well_formed_fallback_report(result, incident)


# F. Missing configuration (Settings has no key; client never constructed) --


def test_missing_configuration_produces_well_formed_fallback():
    incident = make_incident()
    settings = make_settings(api_key=None)
    # investigate() with no injected client attempts to build a real
    # FeatherlessClient from settings -- that construction itself fails.
    result = investigate(incident, settings=settings)
    _assert_well_formed_fallback_report(result, incident)


# --- direct fallback_investigation() contract-level checks --------------


def test_fallback_never_claims_an_llm_explanation_exists():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    # the exact literal must be present in both prose fields -- no
    # paraphrase that could be mistaken for an actual AI explanation
    for text in (result.root_cause, result.attack_narrative):
        assert "AI EXPLANATION:\nUnavailable" in text


def test_fallback_confirmed_and_inference_sections_use_only_evidence_derived_text():
    # With sensitive resource access AND an external destination both
    # present, the narrative must state the confirmed fact and the
    # deterministic inference distinctly (matches the checkpoint's own
    # worked example).
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert "Agent accessed confirmed sensitive resource(s): customer_database." in result.attack_narrative
    assert "Sensitive data reached an external destination." in result.attack_narrative


def test_fallback_uses_only_deterministic_evidence_never_invents_facts():
    # Evidence naming a resource/event not present anywhere else must not
    # cause any different or additional claim to appear -- the fallback
    # only ever restates exactly what's in the dict it was given.
    evidence = {
        "incident_type": "TEST_TYPE",
        "attack_path": ["E1"],
        "sensitive_resources_accessed": [{"resource": "only_this_resource"}],
        "external_destinations": [{"event_id": "E1"}],
    }
    result = fallback_investigation(evidence)

    assert "only_this_resource" in result.attack_narrative
    assert "TEST_TYPE" in result.root_cause
    # nothing about a resource/event that was never supplied
    assert "customer_database" not in result.attack_narrative

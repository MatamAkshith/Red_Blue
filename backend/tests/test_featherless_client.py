import json
from types import SimpleNamespace

import httpx2
import openai
import pytest

from app.core.config import Settings
from app.understand.featherless.client import FeatherlessClient, FeatherlessError

VALID_INVESTIGATION = {
    "root_cause": "Untrusted retrieval influenced a privileged tool call",
    "attack_narrative": "A malicious document led the agent to access the CRM.",
    "critical_decision": {"event_id": "E15", "explanation": "Treated content as instruction"},
    "evidence_interpretation": [{"event_id": "E14", "interpretation": "Untrusted source"}],
    "confidence": 0.9,
    "contributing_factors": ["No sanitization"],
    "failure_pattern_candidate": None,
}


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="featherless/test-model",
    )


def fake_completion(content: str):
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


def test_missing_api_key_raises():
    with pytest.raises(FeatherlessError):
        FeatherlessClient(make_settings(api_key=None))


def test_successful_analyze_parses_and_validates(monkeypatch):
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(VALID_INVESTIGATION)),
    )

    result = client.analyze({"incident_id": "INC-1"})
    assert result.root_cause.startswith("Untrusted retrieval")
    assert result.critical_decision.event_id == "E15"


def test_markdown_fenced_json_is_still_parsed(monkeypatch):
    client = FeatherlessClient(make_settings())
    fenced = "```json\n" + json.dumps(VALID_INVESTIGATION) + "\n```"
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion(fenced)
    )

    result = client.analyze({})
    assert result.confidence == 0.9


def test_invalid_json_raises_featherless_error(monkeypatch):
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion("not json")
    )

    with pytest.raises(FeatherlessError, match="not valid JSON"):
        client.analyze({})


def test_schema_validation_failure_raises_featherless_error(monkeypatch):
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps({"root_cause": "x"})),
    )

    with pytest.raises(FeatherlessError, match="schema validation"):
        client.analyze({})


def test_empty_response_raises_featherless_error(monkeypatch):
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions, "create", lambda **kwargs: fake_completion("")
    )

    with pytest.raises(FeatherlessError, match="empty response"):
        client.analyze({})


def test_connection_error_is_mapped(monkeypatch):
    client = FeatherlessClient(make_settings())
    request = httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")

    def raise_connection_error(**kwargs):
        raise openai.APIConnectionError(request=request)

    monkeypatch.setattr(client._client.chat.completions, "create", raise_connection_error)

    with pytest.raises(FeatherlessError, match="Could not connect"):
        client.analyze({})


def test_timeout_error_is_mapped(monkeypatch):
    client = FeatherlessClient(make_settings())
    request = httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")

    def raise_timeout(**kwargs):
        raise openai.APITimeoutError(request=request)

    monkeypatch.setattr(client._client.chat.completions, "create", raise_timeout)

    with pytest.raises(FeatherlessError, match="timed out"):
        client.analyze({})


def test_authentication_error_is_mapped(monkeypatch):
    client = FeatherlessClient(make_settings())
    request = httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")
    response = httpx2.Response(401, request=request)

    def raise_auth_error(**kwargs):
        raise openai.AuthenticationError("bad key", response=response, body=None)

    monkeypatch.setattr(client._client.chat.completions, "create", raise_auth_error)

    with pytest.raises(FeatherlessError, match="authentication failed"):
        client.analyze({})


def test_error_messages_never_contain_the_api_key(monkeypatch):
    settings = make_settings(api_key="super-secret-key-value")
    client = FeatherlessClient(settings)
    request = httpx2.Request("POST", "https://api.featherless.ai/v1/chat/completions")

    def raise_connection_error(**kwargs):
        raise openai.APIConnectionError(request=request)

    monkeypatch.setattr(client._client.chat.completions, "create", raise_connection_error)

    with pytest.raises(FeatherlessError) as exc_info:
        client.analyze({})
    assert "super-secret-key-value" not in str(exc_info.value)

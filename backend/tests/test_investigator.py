from app.core.config import Settings
from app.understand.featherless.client import FeatherlessError
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import CriticalDecision, Investigation
from tests.test_contracts import make_incident


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


class _FakeClient:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error
        self.received_evidence = None

    def analyze(self, evidence):
        self.received_evidence = evidence
        if self._error:
            raise self._error
        return self._result


def _sample_investigation() -> Investigation:
    return Investigation(
        root_cause="test root cause",
        attack_narrative="test narrative",
        critical_decision=CriticalDecision(event_id="E15", explanation="test"),
        confidence=0.8,
    )


def test_investigate_uses_client_when_available():
    fake = _FakeClient(result=_sample_investigation())
    incident = make_incident()

    result = investigate(incident, settings=make_settings(), client=fake)

    assert result.root_cause == "test root cause"
    assert fake.received_evidence["incident_id"] == incident.incident_id


def test_investigate_falls_back_on_featherless_error():
    fake = _FakeClient(error=FeatherlessError("boom"))
    incident = make_incident()

    result = investigate(incident, settings=make_settings(), client=fake)

    assert result.confidence == 0.0
    assert "AI EXPLANATION:\nUnavailable" in result.root_cause


def test_investigate_falls_back_when_no_api_key_configured():
    incident = make_incident()

    result = investigate(incident, settings=make_settings(api_key=None))

    assert result.confidence == 0.0
    assert "AI EXPLANATION:\nUnavailable" in result.root_cause

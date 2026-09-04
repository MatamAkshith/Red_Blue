from fastapi.testclient import TestClient

import app.api.routes_investigate as routes_investigate
from app.main import app
from app.understand.featherless.client import FeatherlessError
from app.understand.investigation.schemas import CriticalDecision, Investigation
from tests.test_contracts import make_incident

client = TestClient(app)


def valid_incident_payload() -> dict:
    return make_incident().model_dump(mode="json")


def test_investigate_endpoint_returns_investigation(monkeypatch):
    fake_result = Investigation(
        root_cause="test root cause",
        attack_narrative="test narrative",
        critical_decision=CriticalDecision(event_id="E15", explanation="test"),
        confidence=0.75,
    )
    monkeypatch.setattr(routes_investigate, "investigate", lambda incident: fake_result)

    resp = client.post("/investigate", json=valid_incident_payload())

    assert resp.status_code == 200
    body = resp.json()
    assert body["root_cause"] == "test root cause"
    assert body["critical_decision"]["event_id"] == "E15"
    assert body["confidence"] == 0.75


def test_investigate_endpoint_passes_the_parsed_incident_through(monkeypatch):
    received = {}

    def fake_investigate(incident):
        received["incident_id"] = incident.incident_id
        return Investigation(
            root_cause="x",
            attack_narrative="y",
            critical_decision=CriticalDecision(event_id="E1", explanation="z"),
            confidence=0.5,
        )

    monkeypatch.setattr(routes_investigate, "investigate", fake_investigate)

    client.post("/investigate", json=valid_incident_payload())

    assert received["incident_id"] == "INC-1"


def test_investigate_endpoint_rejects_invalid_payload():
    resp = client.post("/investigate", json={"agent_id": "A1"})
    assert resp.status_code == 422


def test_investigate_endpoint_falls_back_when_featherless_unavailable(monkeypatch):
    # investigate() is left real here, but FeatherlessClient construction is
    # forced to fail -- no network call happens, and this proves the
    # endpoint surfaces the deterministic fallback rather than a 500.
    def raise_unavailable(settings):
        raise FeatherlessError("no key configured")

    monkeypatch.setattr(
        "app.understand.investigation.investigator.FeatherlessClient", raise_unavailable
    )

    resp = client.post("/investigate", json=valid_incident_payload())

    assert resp.status_code == 200
    assert resp.json()["confidence"] == 0.0

from fastapi.testclient import TestClient

import backend.app.api.routes_investigate as routes_investigate
from backend.app.main import app
from backend.app.understand.featherless.client import FeatherlessError
from backend.app.understand.investigation.schemas import CriticalDecision, Investigation
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


def test_investigate_endpoint_never_exposes_the_api_key(monkeypatch):
    # A real-looking key is configured in the environment; the route (via
    # the fallback path here, since Featherless construction is forced to
    # fail) must never let it reach the HTTP response in any form.
    monkeypatch.setenv("FEATHERLESS_API_KEY", "super-secret-test-key-value")

    def raise_unavailable(settings):
        raise FeatherlessError("no key configured")

    monkeypatch.setattr(
        "app.understand.investigation.investigator.FeatherlessClient", raise_unavailable
    )

    resp = client.post("/investigate", json=valid_incident_payload())

    assert resp.status_code == 200
    assert "super-secret-test-key-value" not in resp.text


def test_investigator_package_never_imports_fastapi():
    # Static proof (not just "nothing broke at runtime", which can't tell
    # you this since fastapi is already loaded elsewhere in the same test
    # process) that app.understand.* -- the actual investigation pipeline
    # routes_investigate.py delegates to -- has no FastAPI dependency and
    # is genuinely usable standalone.
    import ast
    import pathlib

    understand_root = pathlib.Path(__file__).resolve().parent.parent / "app" / "understand"
    offending: list[str] = []
    for path in understand_root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "fastapi" in node.module:
                offending.append(str(path))
            elif isinstance(node, ast.Import) and any("fastapi" in a.name for a in node.names):
                offending.append(str(path))

    assert offending == []

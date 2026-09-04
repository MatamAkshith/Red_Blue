from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def valid_payload(event_id: str, session_id: str = "S1") -> dict:
    return {
        "event_id": event_id,
        "session_id": session_id,
        "agent_id": "A1",
        "event_type": "TOOL_CALL",
        "source": "agent",
        "target": "crm",
        "resource": "customer_database",
        "trust_level": "UNTRUSTED",
    }


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_post_valid_event_returns_200():
    resp = client.post("/events", json=valid_payload("E100"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_id"] == "E100"


def test_post_invalid_event_returns_422():
    resp = client.post("/events", json={"session_id": "S1"})
    assert resp.status_code == 422


def test_get_events_returns_submitted_events():
    client.post("/events", json=valid_payload("E200", session_id="S200"))
    client.post("/events", json=valid_payload("E201", session_id="S200"))

    resp = client.get("/events", params={"session_id": "S200"})
    assert resp.status_code == 200
    ids = [e["event_id"] for e in resp.json()]
    assert ids == ["E200", "E201"]


def test_get_events_unknown_session_returns_empty_list():
    resp = client.get("/events", params={"session_id": "does-not-exist"})
    assert resp.status_code == 200
    assert resp.json() == []

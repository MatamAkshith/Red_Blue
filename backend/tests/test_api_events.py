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


def test_run_demo_generates_session_id_and_stores_events():
    resp = client.post("/events/run-demo", json={"scenario": "malicious", "async_run": False})
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["session_id"].startswith("S-LIVE-")
    assert data["status"] == "EXFILTRATED"
    assert data["event_count"] == 6

    # Verify events are stored under the generated session_id
    sess_id = data["session_id"]
    ev_resp = client.get("/events", params={"session_id": sess_id})
    assert ev_resp.status_code == 200
    events = ev_resp.json()
    assert len(events) == 6
    assert all(e["session_id"] == sess_id for e in events)


def test_list_sessions_returns_recent_session_summaries():
    resp = client.post("/events/run-demo", json={"scenario": "malicious", "async_run": False})
    sess_id = resp.json()["session_id"]

    sess_resp = client.get("/events/sessions")
    assert sess_resp.status_code == 200
    sessions = sess_resp.json()
    assert isinstance(sessions, list)
    assert any(s["session_id"] == sess_id for s in sessions)


def test_live_session_analysis_pipeline():
    # 1. Trigger malicious demo
    mal_resp = client.post("/events/run-demo", json={"scenario": "malicious", "async_run": False})
    mal_sess = mal_resp.json()["session_id"]
    mal_events = client.get("/events", params={"session_id": mal_sess}).json()

    # Analyze malicious events
    anal_mal = client.post("/incidents/analyze", json={"events": mal_events, "incident_id": f"INC-{mal_sess}"})
    assert anal_mal.status_code == 200
    mal_body = anal_mal.json()
    finding_types = [f["detector_type"] for f in mal_body.get("findings", [])]
    assert "DATA_EXFILTRATION" in finding_types
    assert "PRIVILEGE_VIOLATION" in finding_types

    # 2. Trigger benign demo
    ben_resp = client.post("/events/run-demo", json={"scenario": "benign", "async_run": False})
    ben_sess = ben_resp.json()["session_id"]
    ben_events = client.get("/events", params={"session_id": ben_sess}).json()

    # Analyze benign events
    anal_ben = client.post("/incidents/analyze", json={"events": ben_events, "incident_id": f"INC-{ben_sess}"})
    assert anal_ben.status_code == 200
    ben_body = anal_ben.json()
    assert len(ben_body.get("findings", [])) == 0
    assert mal_sess != ben_sess

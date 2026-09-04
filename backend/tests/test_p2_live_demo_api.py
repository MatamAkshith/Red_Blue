"""P2 Integration Tests — BLACKBOX Live Target Agent Frontend-Backend API & Telemetry Pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from backend.app.api.routes_events import router as events_router
from backend.app.api.routes_incidents import router as incidents_router
from backend.app.events.collector import EventCollector
from backend.app.events.storage import EventStore
from backend.app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_p2_run_demo_malicious_scenario(client):
    """Verify POST /events/run-demo (sync mode) executes malicious scenario and ingests telemetry."""
    session_id = "S-TEST-P2-MALICIOUS"
    payload = {
        "scenario": "malicious",
        "session_id": session_id,
        "demo_delay": 0.0,
        "async_run": False,
    }
    response = client.post("/events/run-demo", json=payload)
    assert response.status_code == 200, response.text

    data = response.json()
    assert data["session_id"] == session_id
    assert data["scenario"] == "malicious"
    assert data["status"] in ("EXFILTRATED", "completed", "COMPLETED")
    assert data["event_count"] == 6

    events = data["events"]
    assert len(events) == 6

    # Verify event types and lineage
    event_ids = [e["event_id"] for e in events]
    assert event_ids == ["E1", "E2", "E3", "E4", "E5", "E6"]

    assert events[0]["event_type"] == "INPUT"
    assert events[1]["event_type"] == "RETRIEVAL"
    assert events[2]["event_type"] == "DECISION"
    assert events[3]["event_type"] == "TOOL_CALL"
    assert events[4]["event_type"] in ("RETRIEVAL", "TOOL_CALL", "TOOL_RESULT")
    assert events[5]["event_type"] in ("ACTION", "TOOL_RESULT")

    # Parent ID causal links
    assert events[0]["parent_event_id"] is None
    assert events[1]["parent_event_id"] == "E1"
    assert events[2]["parent_event_id"] == "E2"
    assert events[3]["parent_event_id"] == "E3"
    assert events[4]["parent_event_id"] in ("E3", "E4")
    assert events[5]["parent_event_id"] in ("E5", "E6")


def test_p2_run_demo_benign_scenario(client):
    """Verify POST /events/run-demo (sync mode) executes benign scenario and ingests telemetry."""
    session_id = "S-TEST-P2-BENIGN"
    payload = {
        "scenario": "benign",
        "session_id": session_id,
        "demo_delay": 0.0,
        "async_run": False,
    }
    response = client.post("/events/run-demo", json=payload)
    assert response.status_code == 200, response.text

    data = response.json()
    assert data["session_id"] == session_id
    assert data["scenario"] == "benign"
    assert data["status"] in ("COMPLETED", "completed")
    assert data["event_count"] == 3

    events = data["events"]
    assert len(events) == 3
    event_ids = [e["event_id"] for e in events]
    assert event_ids == ["E1", "E2", "E3"]


def test_p2_get_session_events(client):
    """Verify GET /events?session_id=... returns stored telemetry events."""
    session_id = "S-TEST-P2-GET-EVENTS"
    # First ingest events via run-demo
    client.post(
        "/events/run-demo",
        json={
            "scenario": "malicious",
            "session_id": session_id,
            "demo_delay": 0.0,
            "async_run": False,
        },
    )

    # Fetch events via GET /events
    get_res = client.get(f"/events?session_id={session_id}")
    assert get_res.status_code == 200, get_res.text

    events = get_res.json()
    assert len(events) == 6
    assert all(e["session_id"] == session_id for e in events)


def test_p2_end_to_end_telemetry_to_analysis(client):
    """Verify full P2 pipeline: Target Agent events -> EventStore -> GET /events -> POST /incidents/analyze."""
    session_id = "S-TEST-P2-E2E"
    # Step 1: Run target demo scenario
    demo_res = client.post(
        "/events/run-demo",
        json={
            "scenario": "malicious",
            "session_id": session_id,
            "demo_delay": 0.0,
            "async_run": False,
        },
    )
    assert demo_res.status_code == 200

    # Step 2: Poll / fetch session events
    fetch_res = client.get(f"/events?session_id={session_id}")
    assert fetch_res.status_code == 200
    events = fetch_res.json()
    assert len(events) == 6

    # Step 3: Run backend security analysis over polled events
    analyze_res = client.post(
        "/incidents/analyze",
        json={
            "events": events,
            "known_sensitive_resources": [],
            "incident_id": f"INC-{session_id}",
            "explain": True,
        },
    )
    assert analyze_res.status_code == 200, analyze_res.text
    analysis_data = analyze_res.json()

    # Step 4: Verify detection engine & AEGIS blast radius
    findings = analysis_data.get("findings", [])
    assert len(findings) > 0, "Backend detection engine must detect malicious exfiltration"
    assert any("EXFILTRATION" in f.get("detector_type", "") or "INJECTION" in f.get("detector_type", "") for f in findings)

    blast_radius = analysis_data.get("blast_radius", {})
    assert blast_radius is not None
    external_dests = blast_radius.get("reachable_external_destinations", [])
    assert len(external_dests) > 0
    assert any("external" in d for d in external_dests)

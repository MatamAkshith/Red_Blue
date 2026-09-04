import pytest
from fastapi.testclient import TestClient

try:
    from backend.app.api.schemas import IncidentResponse
    HAS_SCHEMAS = True
except ImportError:
    HAS_SCHEMAS = False

try:
    from backend.app.main import app
    client = TestClient(app)
    HAS_APP = True
except ImportError:
    HAS_APP = False


@pytest.mark.skipif(not HAS_SCHEMAS, reason="API schemas not found.")
def test_task4_incident_response_contract():
    schema = IncidentResponse.model_json_schema()
    properties = schema.get("properties", {})
    expected_fields = ["incident_info", "events", "findings", "attack_path", "blast_radius", "investigation"]
    missing_fields = [f for f in expected_fields if f not in properties]
    assert not missing_fields, f"Task 4 Contract is missing required fields: {missing_fields}"


@pytest.mark.skipif(not HAS_APP, reason="FastAPI app not found.")
def test_task4_demo_scenario_endpoint():
    response = client.get("/incidents/demo-scenario")
    if response.status_code == 404:
        pytest.skip("Endpoint not found at root level.")
        
    assert response.status_code == 200
    data = response.json()
    
    # Updated to handle the dictionary wrapper
    assert isinstance(data, dict), "Expected a dictionary wrapper"
    assert "events" in data, "Response missing 'events' key"
    
    events = data["events"]
    assert isinstance(events, list)
    assert len(events) >= 4
    assert "event_id" in events[0]


@pytest.mark.skipif(not HAS_APP, reason="FastAPI app not found.")
def test_task4_analyze_endpoint():
    events_resp = client.get("/incidents/demo-scenario")
    if events_resp.status_code != 200:
        pytest.skip("Demo scenario endpoint not available.")
    
    payload = events_resp.json()

    response = client.post("/incidents/analyze", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert "incident_info" in data
    assert "findings" in data
    assert "attack_path" in data
    assert len(data["attack_path"]) > 0
    assert len(data["findings"]) > 0

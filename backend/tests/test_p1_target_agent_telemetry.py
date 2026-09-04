"""P1 Integration Tests — Live Target Agent Telemetry Integration.

Verifies that target EmailProcessingAgent operational steps are translated into valid
universal AgentEvents, ingested through EventCollector / POST /events, persisted in EventStore,
and reconstructed into NetworkX execution graphs by build_execution_graph.
"""

from __future__ import annotations

from pathlib import Path
import tempfile

from fastapi.testclient import TestClient
import pytest

from backend.app.api.routes_events import router as events_router
from backend.app.detection.engine import DetectionEngine
from backend.app.events.collector import EventCollector
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel
from backend.app.events.storage import EventStore
from backend.app.graph.builder import build_execution_graph
from backend.app.main import app
from backend.app.target.adapter import AgentEventAdapter
from backend.app.target.email_agent import EmailProcessingAgent
from backend.app.target.runner import run_target_scenario


@pytest.fixture
def tmp_event_store(tmp_path: Path) -> EventStore:
    return EventStore(tmp_path / "test_p1_events.db")


@pytest.fixture
def event_collector(tmp_event_store: EventStore) -> EventCollector:
    return EventCollector(tmp_event_store)


def test_adapter_translates_steps_to_valid_agent_events(event_collector: EventCollector) -> None:
    session_id = "S-TEST-P1-001"
    adapter = AgentEventAdapter(collector=event_collector, session_id=session_id)
    agent = EmailProcessingAgent(step_listener=adapter.create_listener())

    # Execute benign workflow
    result = agent.process_email("email-benign-1")
    assert result.status == "COMPLETED"

    # Verify emitted events
    emitted = adapter.emitted_events
    assert len(emitted) == 3

    # Check session consistency
    for ev in emitted:
        assert ev.session_id == session_id
        assert ev.agent_id == "agent-email-processor"

    # Step 1: INPUT
    e1 = emitted[0]
    assert e1.event_id == "E1"
    assert e1.parent_event_id is None
    assert e1.event_type == EventType.INPUT
    assert e1.source == "user"
    assert e1.trust_level == TrustLevel.TRUSTED

    # Step 2: RETRIEVAL
    e2 = emitted[1]
    assert e2.event_id == "E2"
    assert e2.parent_event_id == "E1"
    assert e2.event_type == EventType.RETRIEVAL
    assert e2.source == "untrusted"
    assert e2.resource == "doc://benign_onboarding_guide.txt"
    assert e2.trust_level == TrustLevel.UNTRUSTED

    # Step 3: DECISION
    e3 = emitted[2]
    assert e3.event_id == "E3"
    assert e3.parent_event_id == "E2"
    assert e3.event_type == EventType.DECISION


def test_malicious_scenario_produces_full_causal_telemetry_trace(event_collector: EventCollector) -> None:
    session_id = "S-TEST-P1-MALICIOUS"
    adapter = AgentEventAdapter(collector=event_collector, session_id=session_id)
    agent = EmailProcessingAgent(step_listener=adapter.create_listener())

    # Execute malicious workflow
    result = agent.process_email("email-malicious-1")
    assert result.status == "EXFILTRATED"

    # Verify emitted events
    emitted = adapter.emitted_events
    assert len(emitted) == 6

    # Verify causal parent-child lineage
    expected_lineage = [
        ("E1", None, EventType.INPUT),
        ("E2", "E1", EventType.RETRIEVAL),
        ("E3", "E2", EventType.DECISION),
        ("E4", "E3", EventType.TOOL_CALL),
        ("E5", "E4", EventType.TOOL_RESULT),
        ("E6", "E5", EventType.ACTION),
    ]

    for ev, (exp_id, exp_parent, exp_type) in zip(emitted, expected_lineage):
        assert ev.event_id == exp_id
        assert ev.parent_event_id == exp_parent
        assert ev.event_type == exp_type
        assert ev.session_id == session_id

    # Verify persistence in EventStore
    stored = event_collector.get_session(session_id)
    assert len(stored) == 6
    assert [e.event_id for e in stored] == ["E1", "E2", "E3", "E4", "E5", "E6"]


def test_stored_telemetry_builds_valid_execution_graph(event_collector: EventCollector) -> None:
    session_id = "S-TEST-GRAPH-BUILD"
    adapter = AgentEventAdapter(collector=event_collector, session_id=session_id)
    agent = EmailProcessingAgent(step_listener=adapter.create_listener())

    agent.process_email("email-malicious-1")

    # Fetch stored events and reconstruct execution graph
    events = event_collector.get_session(session_id)
    graph = build_execution_graph(events)

    assert graph.number_of_nodes() == 6
    assert graph.number_of_edges() == 5
    assert graph.graph.get("_blackbox_validated") is True

    # Verify directed edges follow causal order
    assert list(graph.successors("E1")) == ["E2"]
    assert list(graph.successors("E2")) == ["E3"]
    assert list(graph.successors("E3")) == ["E4"]
    assert list(graph.successors("E4")) == ["E5"]
    assert list(graph.successors("E5")) == ["E6"]


def test_detection_engine_evaluates_target_agent_telemetry(event_collector: EventCollector) -> None:
    session_id = "S-TEST-DETECTION"
    adapter = AgentEventAdapter(collector=event_collector, session_id=session_id)
    agent = EmailProcessingAgent(step_listener=adapter.create_listener())

    agent.process_email("email-malicious-1")
    events = event_collector.get_session(session_id)
    graph = build_execution_graph(events)

    # Run BLACKBOX DetectionEngine on the live trace
    engine = DetectionEngine()
    findings = engine.run(graph)

    # Detection engine must find prompt injection, privilege violation, or data exfiltration
    assert len(findings) >= 1
    detector_types = [f.detector_type for f in findings]
    assert any(
        dt in detector_types
        for dt in ["PROMPT_INJECTION", "DATA_EXFILTRATION", "PRIVILEGE_VIOLATION"]
    )


def test_fastapi_post_events_endpoint_ingestion() -> None:
    client = TestClient(app)
    session_id = "S-TEST-HTTP-EVENTS"

    # Define submit function calling FastAPI client POST /events
    def http_submit(raw_event: dict) -> dict:
        response = client.post("/events", json=raw_event)
        assert response.status_code == 200, f"POST /events failed: {response.text}"
        return response.json()

    adapter = AgentEventAdapter(submit_fn=http_submit, session_id=session_id)
    agent = EmailProcessingAgent(step_listener=adapter.create_listener())

    # Process malicious scenario via HTTP POST /events
    result = agent.process_email("email-malicious-1")
    assert result.status == "EXFILTRATED"
    assert len(adapter.emitted_events) == 6


def test_runner_live_mode() -> None:
    result, events = run_target_scenario("malicious", live=True)
    assert result.status == "EXFILTRATED"
    assert len(events) == 6

    # Verify graph can be constructed
    graph = build_execution_graph(events)
    assert graph.number_of_nodes() == 6

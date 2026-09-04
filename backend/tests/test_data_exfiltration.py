import pytest
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel
from backend.app.graph.builder import build_execution_graph
from backend.app.detection import DataExfiltrationDetector, DetectionEngine, DetectorType, Severity


def test_true_positive_exfiltration():
    # CRITICAL DB access -> tool call -> EXTERNAL endpoint
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="agent",
        resource="db://sensitive_customer_pii",
        metadata={"sensitivity": "CRITICAL"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )
    e3 = AgentEvent(
        event_id="e3",
        parent_event_id="e2",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        target="https://api.external-untrusted-receiver.com/upload",
        action="export",
        trust_level=TrustLevel.UNTRUSTED,
    )

    graph = build_execution_graph([e1, e2, e3])
    detector = DataExfiltrationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 1
    f = findings[0]
    assert f.detector_type == DetectorType.DATA_EXFILTRATION
    assert f.severity == Severity.CRITICAL
    assert f.confidence == 1.0
    assert f.event_ids == ["e1", "e2", "e3"]
    assert f.graph_path == ["e1", "e2", "e3"]


def test_true_negative_public_data():
    # Public DB access (sensitivity LOW) -> tool call -> EXTERNAL endpoint
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="agent",
        resource="db://public_news",
        metadata={"sensitivity": "LOW"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        target="https://api.external-site.com/post",
        trust_level=TrustLevel.UNTRUSTED,
    )

    graph = build_execution_graph([e1, e2])
    detector = DataExfiltrationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_true_negative_internal_move():
    # CRITICAL DB access -> tool call -> INTERNAL trusted service
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="agent",
        resource="db://sensitive_vault",
        metadata={"sensitivity": "CRITICAL"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        target="internal_backup_service",
        trust_level=TrustLevel.TRUSTED,
    )

    graph = build_execution_graph([e1, e2])
    detector = DataExfiltrationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_true_negative_disconnected_branches():
    # Branch A: CRITICAL DB access (no external call)
    ea1 = AgentEvent(
        event_id="ea1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
    )
    ea2 = AgentEvent(
        event_id="ea2",
        parent_event_id="ea1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="agent",
        resource="db://sensitive_keys",
        metadata={"sensitivity": "CRITICAL"},
    )

    # Disconnected Branch B: External request (unrelated to sensitive access)
    eb1 = AgentEvent(
        event_id="eb1",
        session_id="s1",
        agent_id="a2",
        event_type=EventType.INPUT,
        source="user2",
    )
    eb2 = AgentEvent(
        event_id="eb2",
        parent_event_id="eb1",
        session_id="s1",
        agent_id="a2",
        event_type=EventType.ACTION,
        source="a2",
        target="https://api.external-weather.com/get",
        trust_level=TrustLevel.UNTRUSTED,
    )

    graph = build_execution_graph([ea1, ea2, eb1, eb2])
    detector = DataExfiltrationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_determinism_multiple_runs():
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="agent",
        resource="db://sensitive_financials",
        metadata={"sensitivity": "HIGH"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        target="https://api.exfil-dest.com",
        trust_level=TrustLevel.UNTRUSTED,
    )

    graph = build_execution_graph([e1, e2])
    engine = DetectionEngine()
    engine.register_detector(DataExfiltrationDetector())

    f1 = engine.run(graph)
    f2 = engine.run(graph)

    assert len(f1) == 1
    assert f1[0].model_dump() == f2[0].model_dump()

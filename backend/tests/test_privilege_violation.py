import pytest
from app.events.schemas import AgentEvent, EventType
from app.graph.builder import build_execution_graph
from app.detection import DetectionEngine, DetectorType, PrivilegeViolationDetector, Severity


def test_true_positive_escalation():
    # Agent granted READ, attempts WRITE action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
        metadata={"granted_permission": "read"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.TOOL_CALL,
        source="a1",
        target="database",
        action="write",
        resource="db://users",
    )

    graph = build_execution_graph([e1, e2])
    detector = PrivilegeViolationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 1
    f = findings[0]
    assert f.detector_type == DetectorType.PRIVILEGE_VIOLATION
    assert f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    assert f.confidence == 1.0
    assert "e2" in f.event_ids
    assert f.evidence["granted_permission"] == "read"
    assert f.evidence["required_permission"] == "write"


def test_true_negative_authorized_write():
    # Agent granted WRITE, attempts WRITE action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
        metadata={"granted_permission": "write"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.TOOL_CALL,
        source="a1",
        target="database",
        action="write",
    )

    graph = build_execution_graph([e1, e2])
    detector = PrivilegeViolationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_true_negative_low_privilege_read():
    # Agent granted READ, attempts READ action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
        permission="read",
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="read",
        permission="read",
    )

    graph = build_execution_graph([e1, e2])
    detector = PrivilegeViolationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_branching_isolation():
    # Agent granted READ
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
        metadata={"granted_permission": "read"},
    )

    # Branch A: Safe READ
    e_safe = AgentEvent(
        event_id="e_safe",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="read",
    )

    # Branch B: Malicious ADMIN / DELETE
    e_mal = AgentEvent(
        event_id="e_mal",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.TOOL_CALL,
        source="a1",
        action="delete",
        metadata={"required_permission": "admin"},
    )

    graph = build_execution_graph([e1, e_safe, e_mal])
    detector = PrivilegeViolationDetector()
    findings = detector.detect(graph)

    assert len(findings) == 1
    f = findings[0]
    assert "e_mal" in f.event_ids
    assert "e_safe" not in f.event_ids
    assert f.severity == Severity.CRITICAL # GAP: READ (1) -> ADMIN (5) is CRITICAL


def test_determinism_multiple_runs():
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="user",
        metadata={"granted_permission": "none"},
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.TOOL_CALL,
        source="a1",
        action="execute",
        metadata={"required_permission": "execute"},
    )

    graph = build_execution_graph([e1, e2])
    engine = DetectionEngine()
    engine.register_detector(PrivilegeViolationDetector())

    f1 = engine.run(graph)
    f2 = engine.run(graph)

    assert len(f1) == 1
    assert f1[0].model_dump() == f2[0].model_dump()

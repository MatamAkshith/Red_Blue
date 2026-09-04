import pytest
import networkx as nx
from pydantic import ValidationError

from backend.app.detection import (
    BaseDetector,
    DetectionEngine,
    DetectionError,
    DetectionFinding,
    DetectorType,
    Severity,
)
from backend.app.events.schemas import AgentEvent, EventType
from backend.app.graph.builder import build_execution_graph


class DummyDetectorA(BaseDetector):
    detector_type = DetectorType.INDIRECT_PROMPT_INJECTION

    def detect(self, graph: nx.DiGraph) -> list[DetectionFinding]:
        return [
            DetectionFinding(
                finding_id="find_002",
                detector_type=DetectorType.INDIRECT_PROMPT_INJECTION,
                title="Indirect Prompt Injection Detected",
                description="Prompt injection instruction found in retrieved context.",
                severity=Severity.HIGH,
                confidence=0.95,
                event_ids=["evt_002"],
                graph_path=["evt_001", "evt_002"],
                evidence={"matched_pattern": "ignore previous instructions"},
            )
        ]


class DummyDetectorB(BaseDetector):
    detector_type = DetectorType.DATA_EXFILTRATION

    def detect(self, graph: nx.DiGraph) -> list[DetectionFinding]:
        return [
            DetectionFinding(
                finding_id="find_001",
                detector_type=DetectorType.DATA_EXFILTRATION,
                title="Unauthorized Data Exfiltration",
                description="Outbound network transmission of sensitive data.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                event_ids=["evt_003"],
                graph_path=["evt_001", "evt_002", "evt_003"],
                evidence={"destination": "https://untrusted-external.com"},
            )
        ]


def test_detection_finding_instantiation():
    finding = DetectionFinding(
        finding_id="f1",
        detector_type=DetectorType.TOOL_ABUSE,
        title="Unauthorized Tool Use",
        description="Agent invoked unauthorized system tool.",
        severity=Severity.HIGH,
        confidence=0.9,
        event_ids=["e1", "e2"],
        graph_path=["e1", "e2"],
        source="agent_01",
        target="system_tool",
        evidence={"tool_name": "system_tool"},
        metadata={"category": "privilege"},
    )
    assert finding.finding_id == "f1"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9
    assert finding.event_ids == ["e1", "e2"]


def test_detection_finding_field_validation():
    # Missing required event_ids
    with pytest.raises(ValidationError):
        DetectionFinding(
            finding_id="f1",
            detector_type=DetectorType.TOOL_ABUSE,
            title="Title",
            description="Desc",
            severity=Severity.HIGH,
            confidence=0.9,
            event_ids=[], # min_length=1 required
        )

    # Invalid Enum value for severity
    with pytest.raises(ValidationError):
        DetectionFinding(
            finding_id="f1",
            detector_type=DetectorType.TOOL_ABUSE,
            title="Title",
            description="Desc",
            severity="INVALID_SEVERITY",
            confidence=0.9,
            event_ids=["e1"],
        )

    # Invalid confidence value > 1.0
    with pytest.raises(ValidationError):
        DetectionFinding(
            finding_id="f1",
            detector_type=DetectorType.TOOL_ABUSE,
            title="Title",
            description="Desc",
            severity=Severity.MEDIUM,
            confidence=1.5,
            event_ids=["e1"],
        )


def test_deterministic_serialization():
    finding = DetectionFinding(
        finding_id="f1",
        detector_type=DetectorType.PRIVILEGE_VIOLATION,
        title="Privilege Escalation",
        description="Event elevated user role to admin.",
        severity=Severity.CRITICAL,
        confidence=1.0,
        event_ids=["e1"],
    )
    dump1 = finding.model_dump()
    dump2 = finding.model_dump()
    assert dump1 == dump2
    assert dump1["finding_id"] == "f1"
    assert dump1["severity"] == "CRITICAL"


def test_engine_registration():
    engine = DetectionEngine(register_defaults=False)
    det_a = DummyDetectorA()
    det_b = DummyDetectorB()

    engine.register_detector(det_a)
    engine.register_detector(det_b)

    assert len(engine.detectors) == 2
    assert engine.detectors[0] is det_a
    assert engine.detectors[1] is det_b


def test_empty_and_invalid_graph_handling():
    engine = DetectionEngine(register_defaults=False)
    engine.register_detector(DummyDetectorA())

    # None graph raises DetectionError
    with pytest.raises(DetectionError, match="Execution graph cannot be None"):
        engine.run(None)

    # Empty graph returns []
    empty_graph = nx.DiGraph()
    assert engine.run(empty_graph) == []


def test_output_determinism_and_severity_sorting():
    engine = DetectionEngine(register_defaults=False)
    # Register detectors in arbitrary order (DetectorA is HIGH severity find_002, DetectorB is CRITICAL severity find_001)
    engine.register_detector(DummyDetectorA())
    engine.register_detector(DummyDetectorB())

    g = build_execution_graph([
        AgentEvent(event_id="evt_001", session_id="session-1", agent_id="agent-1", event_type=EventType.INPUT, source="user"),
        AgentEvent(event_id="evt_002", parent_event_id="evt_001", session_id="session-1", agent_id="agent-1", event_type=EventType.DECISION, source="agent"),
        AgentEvent(event_id="evt_003", parent_event_id="evt_002", session_id="session-1", agent_id="agent-1", event_type=EventType.ACTION, source="agent"),
    ])

    # Execute 50 times to guarantee output order determinism
    for _ in range(50):
        findings = engine.run(g)
        assert len(findings) == 2
        # CRITICAL finding (DummyDetectorB / find_001) must come before HIGH finding (DummyDetectorA / find_002)
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].finding_id == "find_001"
        assert findings[1].severity == Severity.HIGH
        assert findings[1].finding_id == "find_002"

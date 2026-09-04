import pytest
import networkx as nx
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph.builder import build_execution_graph
from app.detection import DetectionEngine, DetectionError, DetectorType, Severity


def test_empty_and_none_graph():
    engine = DetectionEngine(register_defaults=True)

    # Empty graph returns []
    empty_graph = nx.DiGraph()
    assert engine.run(empty_graph) == []

    # None graph raises DetectionError
    with pytest.raises(DetectionError, match="Execution graph cannot be None"):
        engine.run(None)


def test_clean_graph_no_attacks():
    engine = DetectionEngine(register_defaults=True)

    # Safe execution: Trusted input -> decision -> safe read action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.INPUT,
        source="trusted_user",
        trust_level=TrustLevel.TRUSTED,
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
        action="read",
        permission="read",
        resource="db://public_info",
    )

    graph = build_execution_graph([e1, e2, e3])
    findings = engine.run(graph)
    assert findings == []


def test_single_detector_trigger():
    engine = DetectionEngine(register_defaults=True)

    # Only privilege escalation: Agent (granted READ) -> ACTION (admin/delete)
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
        event_type=EventType.ACTION,
        source="a1",
        action="delete",
        metadata={"required_permission": "admin"},
    )

    graph = build_execution_graph([e1, e2])
    findings = engine.run(graph)

    assert len(findings) == 1
    assert findings[0].detector_type == DetectorType.PRIVILEGE_VIOLATION
    assert findings[0].severity == Severity.CRITICAL


def test_multiple_detectors_trigger():
    engine = DetectionEngine(register_defaults=True)

    # Complex attack scenario:
    # 1. Untrusted Prompt Injection retrieval (e_ret) -> Decision (e_dec) -> Privileged tool call (e_act1)
    # 2. Sensitive DB access (e_sens) -> External HTTP transmission (e_act2)
    e_ret = AgentEvent(
        event_id="e_ret",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="untrusted_web",
        trust_level=TrustLevel.UNTRUSTED,
    )
    e_dec = AgentEvent(
        event_id="e_dec",
        parent_event_id="e_ret",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )
    e_act1 = AgentEvent(
        event_id="e_act1",
        parent_event_id="e_dec",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="execute",
        permission="privileged",
    )

    e_sens = AgentEvent(
        event_id="e_sens",
        parent_event_id="e_dec",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="a1",
        resource="db://sensitive_credentials",
        metadata={"sensitivity": "CRITICAL"},
    )
    e_act2 = AgentEvent(
        event_id="e_act2",
        parent_event_id="e_sens",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        target="https://api.exfiltrate-untrusted-server.com",
        trust_level=TrustLevel.UNTRUSTED,
        action="export",
    )

    graph = build_execution_graph([e_ret, e_dec, e_act1, e_sens, e_act2])
    findings = engine.run(graph)

    assert len(findings) >= 2
    types_found = {f.detector_type for f in findings}
    assert DetectorType.INDIRECT_PROMPT_INJECTION in types_found
    assert DetectorType.DATA_EXFILTRATION in types_found

    # Assert CRITICAL finding comes first due to severity priority sorting
    assert findings[0].severity == Severity.CRITICAL


def test_engine_determinism_multiple_runs():
    engine = DetectionEngine(register_defaults=True)

    e_ret = AgentEvent(
        event_id="e_ret",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="untrusted_web",
        trust_level=TrustLevel.UNTRUSTED,
    )
    e_dec = AgentEvent(
        event_id="e_dec",
        parent_event_id="e_ret",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )
    e_act = AgentEvent(
        event_id="e_act",
        parent_event_id="e_dec",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="write",
        permission="privileged",
    )

    graph = build_execution_graph([e_ret, e_dec, e_act])

    run1 = engine.run(graph)
    run2 = engine.run(graph)

    assert len(run1) == len(run2)
    for f1, f2 in zip(run1, run2):
        assert f1.model_dump() == f2.model_dump()

import pytest
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph.builder import build_execution_graph
from app.detection import DetectionEngine, DetectorType, PromptInjectionDetector, Severity


def test_true_positive_behavioral():
    # Untrusted retrieval -> decision -> privileged action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="untrusted_web_doc",
        trust_level=TrustLevel.UNTRUSTED,
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
        target="db_admin",
        action="write",
        permission="privileged",
    )

    graph = build_execution_graph([e1, e2, e3])
    detector = PromptInjectionDetector()
    findings = detector.detect(graph)

    assert len(findings) == 1
    f = findings[0]
    assert f.detector_type == DetectorType.INDIRECT_PROMPT_INJECTION
    assert f.severity == Severity.HIGH
    assert f.confidence == 1.0
    assert f.event_ids == ["e1", "e2", "e3"]
    assert f.graph_path == ["e1", "e2", "e3"]


def test_true_negative_normal_rag():
    # Trusted retrieval -> decision -> normal tool call
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="trusted_kb",
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
        permission="none",
    )

    graph = build_execution_graph([e1, e2, e3])
    detector = PromptInjectionDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_true_negative_harmless_external():
    # Untrusted retrieval -> decision -> safe/read-only action
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="external_news_feed",
        trust_level=TrustLevel.UNTRUSTED,
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
    )

    graph = build_execution_graph([e1, e2, e3])
    detector = PromptInjectionDetector()
    findings = detector.detect(graph)

    assert len(findings) == 0


def test_branching_isolation():
    # Untrusted retrieval -> decision -> branch A (safe) & branch B (malicious tool)
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="untrusted_site",
        trust_level=TrustLevel.UNTRUSTED,
    )
    e2 = AgentEvent(
        event_id="e2",
        parent_event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.DECISION,
        source="a1",
    )

    # Branch A: Safe read
    e_safe = AgentEvent(
        event_id="e_safe",
        parent_event_id="e2",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="read",
        permission="read",
    )

    # Branch B: Privileged write
    e_priv = AgentEvent(
        event_id="e_priv",
        parent_event_id="e2",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.ACTION,
        source="a1",
        action="write",
        permission="privileged",
    )

    graph = build_execution_graph([e1, e2, e_safe, e_priv])
    detector = PromptInjectionDetector()
    findings = detector.detect(graph)

    assert len(findings) == 1
    f = findings[0]
    assert f.event_ids == ["e1", "e2", "e_priv"]
    assert f.graph_path == ["e1", "e2", "e_priv"]


def test_determinism_multiple_runs():
    e1 = AgentEvent(
        event_id="e1",
        session_id="s1",
        agent_id="a1",
        event_type=EventType.RETRIEVAL,
        source="untrusted_site",
        trust_level=TrustLevel.UNTRUSTED,
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
        action="execute",
        permission="admin",
    )

    graph = build_execution_graph([e1, e2, e3])
    engine = DetectionEngine()
    engine.register_detector(PromptInjectionDetector())

    f1 = engine.run(graph)
    f2 = engine.run(graph)

    assert len(f1) == 1
    assert f1[0].model_dump() == f2[0].model_dump()

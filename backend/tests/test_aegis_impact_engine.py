import pytest

from backend.app.aegis.blast_radius import Severity
from backend.app.aegis.engine import ImpactAnalysisError, ImpactEngine
from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.detection.models import DetectionFinding, DetectorType, Severity as DetectionSeverity
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel
from backend.app.graph.builder import build_execution_graph


def event(
    event_id: str,
    *,
    parent_event_id: str | None = None,
    event_type: EventType = EventType.DECISION,
    agent_id: str = "agent-1",
    resource: str | None = None,
    target: str | None = None,
    action: str | None = None,
    permission: str | None = None,
    trust_level: TrustLevel = TrustLevel.TRUSTED,
) -> AgentEvent:
    return AgentEvent(
        event_id=event_id,
        parent_event_id=parent_event_id,
        session_id="session-1",
        agent_id=agent_id,
        event_type=event_type,
        source="agent",
        resource=resource,
        target=target,
        action=action,
        permission=permission,
        trust_level=trust_level,
    )


def finding(
    *event_ids: str,
    detector_type: DetectorType = DetectorType.PRIVILEGE_VIOLATION,
    evidence: dict | None = None,
    graph_path: list[str] | None = None,
) -> DetectionFinding:
    return DetectionFinding(
        finding_id=f"finding-{'-'.join(event_ids)}",
        detector_type=detector_type,
        title="Deterministic finding",
        description="A P1.2 finding used as P1.3 input.",
        severity=DetectionSeverity.HIGH,
        confidence=1.0,
        event_ids=list(event_ids),
        graph_path=graph_path or [],
        evidence=evidence or {},
    )


def sensitive(resource: str, severity: Severity = Severity.SENSITIVE) -> SensitiveResource:
    return SensitiveResource(resource=resource, severity=severity)


def test_no_downstream_impact():
    graph = build_execution_graph([event("E1")])

    result = ImpactEngine().analyze_finding(graph, finding("E1"))

    assert result.affected_event_ids == ("E1",)
    assert result.affected_resources == ()
    assert result.supporting_graph_paths == ()
    assert result.blast_radius.risk_score == 0.0


def test_single_downstream_resource():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", event_type=EventType.TOOL_CALL, target="crm", resource="crm://customers"),
    ])

    result = ImpactEngine().analyze_finding(graph, finding("E1"))

    assert result.affected_event_ids == ("E1", "E2")
    assert result.affected_resources == ("crm://customers",)
    assert result.affected_tools == ("crm",)
    assert result.supporting_graph_paths == (("E1", "E2"),)


def test_multiple_downstream_resources():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://customer"),
        event("E3", parent_event_id="E2", resource="vault://credentials"),
    ])

    result = ImpactEngine().analyze_finding(graph, finding("E1"))

    assert result.affected_resources == ("db://customer", "vault://credentials")


def test_sensitive_resource_is_reachable_only_when_registered():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://customer"),
    ])

    result = ImpactEngine().analyze_finding(
        graph,
        finding("E1"),
        known_sensitive_resources=(sensitive("db://customer"), sensitive("db://other")),
    )

    assert [resource.resource for resource in result.reachable_sensitive_resources] == ["db://customer"]


def test_external_destination_is_reused_from_data_exfiltration_evidence():
    destination = "https://external.example/upload"
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", event_type=EventType.ACTION, target=destination, action="export"),
    ])

    result = ImpactEngine().analyze_finding(
        graph,
        finding(
            "E1",
            detector_type=DetectorType.DATA_EXFILTRATION,
            evidence={"destination": destination},
        ),
    )

    assert result.reachable_external_destinations == (destination,)
    assert result.blast_radius.reachable_external_destinations == (destination,)


def test_branching_execution_graph_has_proven_paths_for_each_branch():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://one"),
        event("E3", parent_event_id="E1", resource="db://two", trust_level=TrustLevel.UNTRUSTED),
    ])

    result = ImpactEngine().analyze_finding(graph, finding("E1"))

    assert result.affected_event_ids == ("E1", "E2", "E3")
    assert result.supporting_graph_paths == (("E1", "E2"), ("E1", "E3"))
    assert result.trust_boundary_event_ids == ("E3",)


def test_multiple_findings_produce_distinguishable_results():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1"),
        event("E3", parent_event_id="E2"),
    ])

    results = ImpactEngine().analyze(graph, (finding("E1"), finding("E2")))

    assert [result.finding_id for result in results] == ["finding-E1", "finding-E2"]
    assert results[0].affected_event_ids == ("E1", "E2", "E3")
    assert results[1].affected_event_ids == ("E2", "E3")


def test_finding_references_valid_graph_events():
    graph = build_execution_graph([event("E1"), event("E2", parent_event_id="E1")])

    result = ImpactEngine().analyze_finding(graph, finding("E1", "E2", graph_path=["E1", "E2"]))

    assert result.finding_id == "finding-E1-E2"


def test_finding_references_invalid_or_missing_events_fail_safely():
    graph = build_execution_graph([event("E1"), event("E2")])

    with pytest.raises(ImpactAnalysisError, match="absent from graph"):
        ImpactEngine().analyze_finding(graph, finding("missing"))

    with pytest.raises(ImpactAnalysisError, match="non-graph edge"):
        ImpactEngine().analyze_finding(graph, finding("E1", "E2", graph_path=["E1", "E2"]))


def test_repeated_execution_is_deterministic():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://customer"),
    ])
    source_finding = finding("E1")

    first = ImpactEngine().analyze_finding(graph, source_finding, known_sensitive_resources=(sensitive("db://customer"),))
    second = ImpactEngine().analyze_finding(graph, source_finding, known_sensitive_resources=(sensitive("db://customer"),))

    assert first == second
    assert first.model_dump() == second.model_dump()


def test_blast_radius_uses_existing_highest_reached_resource_weight():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://critical"),
        event("E3", parent_event_id="E1", resource="db://internal"),
    ])

    result = ImpactEngine().analyze_finding(
        graph,
        finding("E1"),
        known_sensitive_resources=(
            sensitive("db://internal", Severity.INTERNAL),
            sensitive("db://critical", Severity.CRITICAL),
        ),
    )

    assert result.blast_radius.reachable_sensitive_resources == ("db://critical", "db://internal")
    assert result.blast_radius.risk_score == float(Severity.CRITICAL.value)


def test_impact_analysis_does_not_mutate_the_graph():
    graph = build_execution_graph([
        event("E1"),
        event("E2", parent_event_id="E1", resource="db://customer"),
    ])
    nodes_before = [(node, data["event"]) for node, data in graph.nodes(data=True)]
    edges_before = list(graph.edges())

    ImpactEngine().analyze_finding(graph, finding("E1"), known_sensitive_resources=(sensitive("db://customer"),))

    assert [(node, data["event"]) for node, data in graph.nodes(data=True)] == nodes_before
    assert list(graph.edges()) == edges_before

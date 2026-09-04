"""P1.3 deterministic AEGIS impact analysis.

This module consumes the authoritative P1.1 NetworkX graph and P1.2 finding
contract.  It deliberately delegates graph navigation to ``app.graph`` and
does not run detectors, rebuild an adjacency structure, or infer resource
classification from names.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable

import networkx as nx

from app.aegis.blast_radius import Severity
from app.aegis.models import ImpactResult
from app.contracts.incident_analysis import BlastRadius, EvidenceItem, SensitiveResource
from app.detection.models import DetectionFinding, DetectorType
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph.traversal import get_descendants, get_execution_path


class ImpactAnalysisError(Exception):
    """Raised when a finding cannot be proven against the supplied P1.1 graph."""


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _event_for(graph: nx.DiGraph, event_id: str) -> AgentEvent:
    event = graph.nodes[event_id].get("event")
    if not isinstance(event, AgentEvent):
        raise ImpactAnalysisError(
            f"Graph node '{event_id}' does not contain an authoritative AgentEvent payload"
        )
    return event


def _validate_finding(graph: nx.DiGraph, finding: DetectionFinding) -> tuple[str, ...]:
    referenced = _ordered_unique((*finding.event_ids, *finding.graph_path))
    missing = tuple(event_id for event_id in referenced if not graph.has_node(event_id))
    if missing:
        raise ImpactAnalysisError(
            f"Finding '{finding.finding_id}' references event_id(s) absent from graph: {list(missing)}"
        )

    for event_id in referenced:
        _event_for(graph, event_id)

    for source, target in zip(finding.graph_path, finding.graph_path[1:]):
        if not graph.has_edge(source, target):
            raise ImpactAnalysisError(
                f"Finding '{finding.finding_id}' graph_path contains non-graph edge "
                f"'{source}' -> '{target}'"
            )

    return _ordered_unique(finding.event_ids)


def _external_destinations(
    finding: DetectionFinding, affected_events: Collection[AgentEvent]
) -> tuple[str, ...]:
    """Return destinations already established by P1.2 exfiltration evidence.

    P1.3 must not replicate P1.2's external-boundary heuristics. The data
    exfiltration detector records its proven destination under ``destination``;
    accept it only when it is present on a reached graph event.
    """

    if finding.detector_type != DetectorType.DATA_EXFILTRATION:
        return ()

    destination = finding.evidence.get("destination")
    if not isinstance(destination, str) or not destination:
        return ()

    reached_destinations = {
        value
        for event in affected_events
        for value in (event.target, event.resource)
        if value
    }
    return (destination,) if destination in reached_destinations else ()


def _blast_radius(
    affected_events: Collection[AgentEvent],
    sensitive_resources: tuple[SensitiveResource, ...],
    external_destinations: tuple[str, ...],
) -> BlastRadius:
    """Build the existing P1-to-P2 blast-radius contract deterministically.

    The repository defines resource severity as the AEGIS ``Severity`` weight,
    but defines no escalation formula. Therefore risk_score is exactly the
    highest reached resource weight (or 0.0 when no classified resource is
    reached). External reachability is recorded as a fact, not converted into
    an invented score increment.
    """

    capabilities = _ordered_unique(
        value
        for event in affected_events
        for value in (event.action, event.permission)
        if value
    )
    score = float(max((resource.severity.value for resource in sensitive_resources), default=0))
    return BlastRadius(
        reachable_sensitive_resources=tuple(resource.resource for resource in sensitive_resources),
        reachable_external_destinations=external_destinations,
        affected_capabilities=capabilities,
        risk_score=score,
    )


class ImpactEngine:
    """Analyze downstream impact once per authoritative P1.2 finding."""

    def analyze(
        self,
        graph: nx.DiGraph,
        findings: Collection[DetectionFinding],
        *,
        known_sensitive_resources: Collection[SensitiveResource] = (),
    ) -> tuple[ImpactResult, ...]:
        if not isinstance(graph, nx.DiGraph):
            raise ImpactAnalysisError(
                f"Impact analysis requires nx.DiGraph, got {type(graph).__name__}"
            )

        registry = tuple(known_sensitive_resources)
        results = tuple(
            self.analyze_finding(graph, finding, known_sensitive_resources=registry)
            for finding in findings
        )
        return results

    def analyze_finding(
        self,
        graph: nx.DiGraph,
        finding: DetectionFinding,
        *,
        known_sensitive_resources: Collection[SensitiveResource] = (),
    ) -> ImpactResult:
        source_event_ids = _validate_finding(graph, finding)

        descendants_by_source = {
            source_event_id: get_descendants(graph, source_event_id)
            for source_event_id in source_event_ids
        }
        affected_event_ids = _ordered_unique(
            event_id
            for source_event_id in source_event_ids
            for event_id in (source_event_id, *descendants_by_source[source_event_id])
        )
        affected_events = tuple(_event_for(graph, event_id) for event_id in affected_event_ids)
        session_ids = _ordered_unique(event.session_id for event in affected_events)
        if len(session_ids) != 1:
            raise ImpactAnalysisError(
                f"Finding '{finding.finding_id}' spans multiple sessions: {list(session_ids)}"
            )

        supporting_paths = _ordered_unique_paths(
            get_execution_path(graph, source_event_id, target_event_id)
            for source_event_id in source_event_ids
            for target_event_id in affected_event_ids
            if source_event_id != target_event_id
            and target_event_id in descendants_by_source[source_event_id]
        )
        reached_resources = {event.resource for event in affected_events if event.resource}
        sensitive_resources = tuple(
            sorted(
                (resource for resource in known_sensitive_resources if resource.resource in reached_resources),
                key=lambda resource: resource.resource,
            )
        )
        external_destinations = _external_destinations(finding, affected_events)
        trust_boundary_event_ids = _ordered_unique(
            event.event_id
            for event in affected_events
            if event.trust_level == TrustLevel.UNTRUSTED
        )

        evidence = tuple(
            EvidenceItem(
                event_id=event_id,
                category="impact_source_finding",
                description=f"Event supports detection finding '{finding.finding_id}'.",
            )
            for event_id in source_event_ids
        ) + tuple(
            EvidenceItem(
                event_id=event_id,
                category="trust_boundary_crossing",
                description="Reached event is marked UNTRUSTED in the authoritative AgentEvent.",
            )
            for event_id in trust_boundary_event_ids
        )

        return ImpactResult(
            finding_id=finding.finding_id,
            session_id=session_ids[0],
            affected_event_ids=affected_event_ids,
            affected_agents=_ordered_unique(event.agent_id for event in affected_events),
            affected_resources=_ordered_unique(event.resource for event in affected_events if event.resource),
            affected_tools=_ordered_unique(
                event.target
                for event in affected_events
                if event.event_type == EventType.TOOL_CALL and event.target
            ),
            reachable_external_destinations=external_destinations,
            trust_boundary_event_ids=trust_boundary_event_ids,
            supporting_graph_paths=supporting_paths,
            reachable_sensitive_resources=sensitive_resources,
            blast_radius=_blast_radius(affected_events, sensitive_resources, external_destinations),
            evidence=evidence,
        )


def _ordered_unique_paths(paths: Iterable[list[str]]) -> tuple[tuple[str, ...], ...]:
    return tuple(sorted({tuple(path) for path in paths}))

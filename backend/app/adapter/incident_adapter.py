"""Deterministic P1 -> P2 IncidentAnalysis Adapter.

Translates P1 forensic facts (Execution Graph, Detection Findings, and AEGIS Impact Results)
into the frozen P1 -> P2 IncidentAnalysis contract consumed by the Understand layer.

CRITICAL RESTRAINTS:
- 100% deterministic graph traversals and set mapping.
- No LLMs, Featherless, or heuristic score synthesis.
- Strict validation: rejects mismatched graphs, missing node references, invalid edges, or cross-session inputs.
"""

from __future__ import annotations

import hashlib
from typing import Any, Collection, List, Set, Tuple, Union

import networkx as nx

from .evidence_assembler import assemble_evidence
from .exceptions import AdapterValidationError
from ..aegis.models import ImpactResult
from ..contracts.incident_analysis import (
    BlastRadius,
    EvidenceItem,
    IncidentAnalysis,
    IncidentSeverity,
    PermissionFact,
    SensitiveResource,
)
from ..detection.models import DetectionFinding, Severity as DetectionSeverity
from ..events.schemas import AgentEvent


_SEVERITY_WEIGHTS: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _get_severity_str(val: Any) -> str:
    if hasattr(val, "value"):
        return str(val.value).upper()
    return str(val).upper()


def _map_to_incident_severity(val: str) -> IncidentSeverity:
    clean = val.strip().upper()
    if clean in ("CRITICAL", "4"):
        return IncidentSeverity.CRITICAL
    if clean in ("HIGH", "3"):
        return IncidentSeverity.HIGH
    if clean in ("MEDIUM", "2"):
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


def _extract_event(graph: nx.DiGraph, event_id: str) -> AgentEvent:
    if not graph.has_node(event_id):
        raise AdapterValidationError(f"Referenced event_id '{event_id}' is absent from execution graph")
    event = graph.nodes[event_id].get("event")
    if not isinstance(event, AgentEvent):
        raise AdapterValidationError(f"Graph node '{event_id}' does not contain a valid AgentEvent object")
    return event


def build_incident_analysis(
    graph: nx.DiGraph,
    findings: List[DetectionFinding],
    impact: Union[ImpactResult, Collection[ImpactResult], None] = None,
) -> IncidentAnalysis:
    """Deterministically convert P1 findings, AEGIS impact, and execution graph into IncidentAnalysis.

    Args:
        graph: Authoritative NetworkX DiGraph from P1.1.
        findings: List of validated DetectionFinding objects from P1.2.
        impact: Single ImpactResult or collection of ImpactResults from P1.3 (optional).

    Returns:
        IncidentAnalysis: Immutable P1 -> P2 security evidence contract.

    Raises:
        AdapterValidationError: If graph is None, empty, if findings/impact reference absent nodes/edges,
                                or if inputs span multiple session IDs.
    """
    if graph is None or not isinstance(graph, nx.DiGraph):
        raise AdapterValidationError("Execution graph must be a valid nx.DiGraph instance")
    if len(graph.nodes) == 0:
        raise AdapterValidationError("Execution graph cannot be empty")

    impact_list: List[ImpactResult] = []
    if isinstance(impact, ImpactResult):
        impact_list = [impact]
    elif impact is not None:
        impact_list = list(impact)

    # Step 1: Validate Finding References against Graph
    for finding in findings:
        for eid in finding.event_ids:
            _extract_event(graph, eid)
        for eid in finding.graph_path:
            _extract_event(graph, eid)
        # Check path edge integrity
        if len(finding.graph_path) > 1:
            for u, v in zip(finding.graph_path, finding.graph_path[1:]):
                if not graph.has_edge(u, v):
                    raise AdapterValidationError(
                        f"Finding '{finding.finding_id}' graph_path specifies non-existent edge '{u}' -> '{v}'"
                    )

    # Step 2: Validate Impact References against Graph
    for imp in impact_list:
        for eid in imp.affected_event_ids:
            _extract_event(graph, eid)
        for eid in imp.trust_boundary_event_ids:
            _extract_event(graph, eid)
        for path in imp.supporting_graph_paths:
            for eid in path:
                _extract_event(graph, eid)
            if len(path) > 1:
                for u, v in zip(path, path[1:]):
                    if not graph.has_edge(u, v):
                        raise AdapterValidationError(
                            f"Impact result '{imp.finding_id}' supporting path contains non-existent edge '{u}' -> '{v}'"
                        )

    # Step 3: Extract Session & Agent Identity & Validate Single Session Boundary
    all_referenced_eids: Set[str] = set()
    for f in findings:
        all_referenced_eids.update(f.event_ids)
        all_referenced_eids.update(f.graph_path)
    for imp in impact_list:
        all_referenced_eids.update(imp.affected_event_ids)

    if not all_referenced_eids:
        all_referenced_eids = set(graph.nodes.keys())

    all_events = [_extract_event(graph, eid) for eid in sorted(all_referenced_eids)]
    session_ids = sorted({e.session_id for e in all_events if e.session_id})
    agent_ids = sorted({e.agent_id for e in all_events if e.agent_id})

    if len(session_ids) > 1:
        raise AdapterValidationError(f"Cross-session data rejected: events span multiple sessions {session_ids}")

    primary_session_id = session_ids[0] if session_ids else "unknown_session"
    primary_agent_id = agent_ids[0] if agent_ids else "unknown_agent"

    # Step 4: Deterministic Incident ID
    finding_ids_str = ",".join(sorted(f.finding_id for f in findings))
    id_seed = f"{primary_session_id}:{primary_agent_id}:{finding_ids_str}".encode("utf-8")
    incident_hash = hashlib.sha256(id_seed).hexdigest()[:12]
    incident_id = f"inc_{incident_hash}"

    # Step 5: Incident Type
    detector_types = sorted({_get_severity_str(f.detector_type) for f in findings})
    incident_type = ",".join(detector_types) if detector_types else "POLICY_VIOLATION"

    # Step 6: Severity Determination (Max across findings & reachable sensitive resources)
    max_weight = 1
    for f in findings:
        sev_str = _get_severity_str(f.severity)
        max_weight = max(max_weight, _SEVERITY_WEIGHTS.get(sev_str, 1))

    for imp in impact_list:
        for res in imp.reachable_sensitive_resources:
            r_sev_str = _get_severity_str(res.severity)
            max_weight = max(max_weight, _SEVERITY_WEIGHTS.get(r_sev_str, 1))

    weight_to_sev_name = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    highest_sev_name = weight_to_sev_name.get(max_weight, "LOW")
    incident_severity = _map_to_incident_severity(highest_sev_name)

    # Step 7: Continuous Coherent Attack Path via Graph Topological Sort
    raw_path_nodes: Set[str] = set()

    for f in findings:
        for node in f.graph_path:
            raw_path_nodes.add(node)

    for imp in impact_list:
        for path in imp.supporting_graph_paths:
            for node in path:
                raw_path_nodes.add(node)

    if not raw_path_nodes and findings:
        for f in findings:
            for eid in f.event_ids:
                raw_path_nodes.add(eid)

    if raw_path_nodes:
        subgraph = graph.subgraph(raw_path_nodes)
        try:
            attack_path_nodes = list(nx.topological_sort(subgraph))
        except nx.NetworkXUnfeasible:
            attack_path_nodes = sorted(raw_path_nodes)
    else:
        attack_path_nodes = []

    # Step 8: Permissions Facts
    permission_facts: List[PermissionFact] = []
    seen_perm_keys: Set[Tuple[str, str, str]] = set()

    for node_id in attack_path_nodes:
        ev = _extract_event(graph, node_id)
        if ev.permission or ev.action:
            perm_name = ev.permission or ev.action or "read"
            res_name = ev.resource or ev.target or "unknown_resource"
            granted = True

            for f in findings:
                det_type = _get_severity_str(f.detector_type)
                if det_type in ("PRIVILEGE_VIOLATION", "TOOL_ABUSE") and node_id in f.event_ids:
                    granted = False
                    break

            perm_key = (node_id, res_name, perm_name)
            if perm_key not in seen_perm_keys:
                seen_perm_keys.add(perm_key)
                permission_facts.append(
                    PermissionFact(
                        event_id=node_id,
                        resource=res_name,
                        permission=perm_name,
                        granted=granted,
                    )
                )

    # Step 9: Sensitive Resources
    sensitive_resources_dict: dict[str, SensitiveResource] = {}
    for imp in impact_list:
        for res in imp.reachable_sensitive_resources:
            if res.resource not in sensitive_resources_dict:
                sensitive_resources_dict[res.resource] = res

    sensitive_resources_tuple = tuple(
        sorted(sensitive_resources_dict.values(), key=lambda r: r.resource)
    )

    # Step 10: Blast Radius
    if impact_list:
        all_reachable_res: Set[str] = set()
        all_ext_dests: Set[str] = set()
        all_capabilities: Set[str] = set()
        max_risk_score = 0.0

        for imp in impact_list:
            br = imp.blast_radius
            all_reachable_res.update(br.reachable_sensitive_resources)
            all_ext_dests.update(br.reachable_external_destinations)
            all_capabilities.update(br.affected_capabilities)
            max_risk_score = max(max_risk_score, br.risk_score)

        blast_radius = BlastRadius(
            reachable_sensitive_resources=tuple(sorted(all_reachable_res)),
            reachable_external_destinations=tuple(sorted(all_ext_dests)),
            affected_capabilities=tuple(sorted(all_capabilities)),
            risk_score=max_risk_score,
        )
    else:
        blast_radius = BlastRadius()

    # Step 11: Evidence Items & Provenance Assembly
    evidence_items = assemble_evidence(findings=findings, impact=impact_list, graph=graph)

    return IncidentAnalysis(
        incident_id=incident_id,
        agent_id=primary_agent_id,
        session_id=primary_session_id,
        incident_type=incident_type,
        severity=incident_severity,
        events=all_events,
        attack_path=tuple(attack_path_nodes),
        permissions=tuple(permission_facts),
        sensitive_resources=sensitive_resources_tuple,
        blast_radius=blast_radius,
        evidence=evidence_items,
    )

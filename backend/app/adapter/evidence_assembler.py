"""Deterministic Evidence and Provenance Assembly Module (P1.4.2).

Extracts, validates, deduplicates, and deterministically sorts EvidenceItem objects
from DetectionFindings and AEGIS ImpactResults against the authoritative Execution Graph.

Provenance Rules:
1. Every evidence item must reference a valid event_id existing in graph.nodes.
2. All evidence items must belong to the exact same session_id.
3. Deduplicates identical evidence items (same event_id, category, and description).
4. Sorts deterministically by event timestamp, event_id, category, and description.
"""

from __future__ import annotations

from typing import Collection, List, Optional, Set, Union
import networkx as nx

from ..aegis.models import ImpactResult
from ..contracts.incident_analysis import EvidenceItem
from ..detection.models import DetectionFinding
from ..events.schemas import AgentEvent
from .incident_adapter import AdapterValidationError


def assemble_evidence(
    findings: List[DetectionFinding],
    impact: Union[ImpactResult, Collection[ImpactResult], None] = None,
    graph: Optional[nx.DiGraph] = None,
) -> List[EvidenceItem]:
    """Assemble, validate provenance, deduplicate, and deterministically sort evidence items.

    Args:
        findings: List of DetectionFinding objects.
        impact: Optional single ImpactResult or collection of ImpactResult objects.
        graph: Authoritative NetworkX DiGraph.

    Returns:
        List[EvidenceItem]: Deterministically sorted, provenance-validated evidence items.

    Raises:
        AdapterValidationError: If graph is None, if an event_id is absent from graph,
                                or if evidence spans multiple sessions.
    """
    if graph is None or not isinstance(graph, nx.DiGraph):
        raise AdapterValidationError("Execution graph must be a valid nx.DiGraph instance for evidence assembly")

    impact_list: List[ImpactResult] = []
    if isinstance(impact, ImpactResult):
        impact_list = [impact]
    elif impact is not None:
        impact_list = list(impact)

    raw_items: List[EvidenceItem] = []

    # 1. Extract from DetectionFindings
    for finding in findings:
        det_type_str = str(getattr(finding.detector_type, "value", finding.detector_type)).upper()
        category = "detection_finding"
        if det_type_str == "INDIRECT_PROMPT_INJECTION":
            category = "trust_boundary_crossing"
        elif det_type_str in ("PRIVILEGE_VIOLATION", "TOOL_ABUSE"):
            category = "privilege_change"
        elif det_type_str == "DATA_EXFILTRATION":
            category = "external_transmission"

        for eid in finding.event_ids:
            raw_items.append(
                EvidenceItem(
                    event_id=eid,
                    category=category,
                    description=f"{finding.title}: {finding.description}",
                )
            )

    # 2. Extract from AEGIS ImpactResults
    for imp in impact_list:
        for ev_item in imp.evidence:
            raw_items.append(ev_item)

    if not raw_items:
        return []

    # 3. Provenance Validation & Session Check
    session_ids: Set[str] = set()
    events_by_id: dict[str, AgentEvent] = {}

    for item in raw_items:
        if not graph.has_node(item.event_id):
            raise AdapterValidationError(
                f"Evidence provenance failure: event_id '{item.event_id}' referenced in evidence does not exist in execution graph"
            )

        event = graph.nodes[item.event_id].get("event")
        if not isinstance(event, AgentEvent):
            raise AdapterValidationError(
                f"Evidence provenance failure: graph node '{item.event_id}' does not contain a valid AgentEvent payload"
            )

        events_by_id[item.event_id] = event
        if event.session_id:
            session_ids.add(event.session_id)

    if len(session_ids) > 1:
        sorted_sessions = sorted(session_ids)
        raise AdapterValidationError(
            f"Evidence provenance failure: evidence spans multiple sessions {sorted_sessions}"
        )

    # 4. Deduplication
    unique_items: List[EvidenceItem] = []
    seen: Set[tuple[str, str, str]] = set()

    for item in raw_items:
        key = (item.event_id, item.category, item.description)
        if key not in seen:
            seen.add(key)
            unique_items.append(item)

    # 5. Deterministic Sorting
    def sort_key(item: EvidenceItem) -> tuple:
        ev = events_by_id.get(item.event_id)
        ts_str = ev.timestamp.isoformat() if (ev and ev.timestamp) else ""
        return (ts_str, item.event_id, item.category, item.description)

    unique_items.sort(key=sort_key)
    return unique_items

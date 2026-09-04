"""Execution graph validation module — forensic and structural integrity verification."""

from __future__ import annotations

import networkx as nx
from app.events.schemas import AgentEvent
from app.graph.models import GraphValidationError


def validate_execution_graph(events: list[AgentEvent], graph: nx.DiGraph) -> bool:
    """Validate structural, relational, and forensic integrity of an execution graph against source events.

    Args:
        events: The list of raw validated AgentEvent objects.
        graph: The constructed execution graph (nx.DiGraph).

    Returns:
        bool: True if the graph passes all structural and forensic integrity checks.

    Raises:
        GraphValidationError: If any structural mismatch, missing node/edge, unexpected node/edge,
                             payload identity mismatch, root inconsistency, or cycle is detected.
    """
    event_map = {e.event_id: e for e in events}

    # 1. Node Count Check
    if len(events) != len(graph.nodes):
        raise GraphValidationError(
            f"Node count mismatch: source events contain {len(events)} items, but graph has {len(graph.nodes)} nodes."
        )

    # 2. Node Identity Check (All source events exist in graph)
    for event in events:
        if not graph.has_node(event.event_id):
            raise GraphValidationError(
                f"Missing node: event_id '{event.event_id}' from source events does not exist in graph."
            )

    # 3. No Extra Nodes Check (All graph nodes exist in source events)
    for node_id in graph.nodes:
        if node_id not in event_map:
            raise GraphValidationError(
                f"Unexpected node: graph node '{node_id}' does not correspond to any source event."
            )

    # 4. Event Preservation & Payload Identity Check
    for node_id, data in graph.nodes(data=True):
        stored_event = data.get("event")
        if stored_event is None:
            raise GraphValidationError(
                f"Payload missing: graph node '{node_id}' is missing stored AgentEvent payload."
            )
        if stored_event.event_id != node_id:
            raise GraphValidationError(
                f"Payload identity mismatch: node '{node_id}' contains AgentEvent with event_id '{stored_event.event_id}'."
            )

    # 5. Cycle Detection (DAG Validation)
    if not nx.is_directed_acyclic_graph(graph):
        raise GraphValidationError("Cycle detected: execution graph contains cycles and is not a valid DAG.")

    # 6. Parent Edge Correctness & Root Consistency
    for event in events:
        if event.parent_event_id is None:
            if graph.in_degree(event.event_id) != 0:
                raise GraphValidationError(
                    f"Root inconsistency: root event '{event.event_id}' (parent_event_id=None) has non-zero in-degree."
                )
        else:
            if not graph.has_edge(event.parent_event_id, event.event_id):
                raise GraphValidationError(
                    f"Missing parent edge: event '{event.event_id}' has parent '{event.parent_event_id}', but edge '{event.parent_event_id} -> {event.event_id}' is missing."
                )
            if graph.in_degree(event.event_id) == 0:
                raise GraphValidationError(
                    f"Root inconsistency: non-root event '{event.event_id}' (parent_event_id='{event.parent_event_id}') has in-degree 0."
                )

    # 7. No Unexpected Edges Check
    for u, v in graph.edges:
        target_event = event_map.get(v)
        if target_event is None or target_event.parent_event_id != u:
            raise GraphValidationError(
                f"Unexpected edge: directed edge '{u} -> {v}' is not justified by source event '{v}' parent_event_id ('{getattr(target_event, 'parent_event_id', None)}')."
            )

    return True

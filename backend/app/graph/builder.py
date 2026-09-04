"""Execution graph builder module — deterministic graph construction."""

from __future__ import annotations

import networkx as nx
from backend.app.events.schemas import AgentEvent
from .models import GraphBuildError, GraphValidationError
from .validation import validate_execution_graph


def build_execution_graph(events: list[AgentEvent]) -> nx.DiGraph:
    """Build a directed execution graph (nx.DiGraph) from a sequence of AgentEvents.

    Uses a two-pass approach to ensure input order independence while enforcing
    duplicate event_id rejection, same-session parent integrity, and complete
    structural validation before returning. Parent-child topology, not event
    timestamps, establishes execution lineage.

    Args:
        events: List of validated AgentEvent objects belonging to an execution trace.

    Returns:
        nx.DiGraph: A NetworkX directed graph where each node is an event_id containing
                    the full AgentEvent object, and directed edges represent parent -> child
                    execution relationships.

    Raises:
        GraphBuildError: If a duplicate event_id is encountered or if an event references
                         a parent_event_id that does not exist in the events list.
    """
    graph = nx.DiGraph()
    snapshots: list[AgentEvent] = []

    # Pass 1: Add all nodes and validate uniqueness
    for event in events:
        if graph.has_node(event.event_id):
            raise GraphBuildError(f"Duplicate event_id detected: '{event.event_id}'")
        # The graph owns an independent snapshot. A caller changing its
        # original event or nested metadata later cannot alter graph facts.
        snapshot = event.model_copy(deep=True)
        snapshots.append(snapshot)
        graph.add_node(snapshot.event_id, event=snapshot)

    # Pass 2: Add directed parent -> child edges and validate parent existence
    for event in snapshots:
        if event.parent_event_id is not None:
            if not graph.has_node(event.parent_event_id):
                raise GraphBuildError(
                    f"Missing parent event_id '{event.parent_event_id}' for event '{event.event_id}'"
                )
            graph.add_edge(event.parent_event_id, event.event_id)

    try:
        validate_execution_graph(snapshots, graph)
    except GraphValidationError as exc:
        raise GraphBuildError(f"Invalid execution graph: {exc}") from exc

    # Traversal consumers use this marker to require the authoritative
    # builder path. It is an integrity boundary, not cryptographic proof.
    graph.graph["_blackbox_validated"] = True

    return graph

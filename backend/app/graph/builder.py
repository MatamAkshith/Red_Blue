"""Execution graph builder module — deterministic graph construction."""

from __future__ import annotations

import networkx as nx
from app.events.schemas import AgentEvent
from app.graph.models import GraphBuildError


def build_execution_graph(events: list[AgentEvent]) -> nx.DiGraph:
    """Build a directed execution graph (nx.DiGraph) from a sequence of AgentEvents.

    Uses a two-pass approach to ensure input order independence while enforcing
    duplicate event_id rejection and missing parent integrity validation.

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

    # Pass 1: Add all nodes and validate uniqueness
    for event in events:
        if graph.has_node(event.event_id):
            raise GraphBuildError(f"Duplicate event_id detected: '{event.event_id}'")
        graph.add_node(event.event_id, event=event)

    # Pass 2: Add directed parent -> child edges and validate parent existence
    for event in events:
        if event.parent_event_id is not None:
            if not graph.has_node(event.parent_event_id):
                raise GraphBuildError(
                    f"Missing parent event_id '{event.parent_event_id}' for event '{event.event_id}'"
                )
            graph.add_edge(event.parent_event_id, event.event_id)

    return graph

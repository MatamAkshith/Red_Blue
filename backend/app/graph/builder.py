"""Execution graph builder module — contract definition."""

from __future__ import annotations

import networkx as nx
from app.events.schemas import AgentEvent
from app.graph.models import GraphBuildError


def build_execution_graph(events: list[AgentEvent]) -> nx.DiGraph:
    """Build a directed execution graph (nx.DiGraph) from a sequence of AgentEvents.

    Args:
        events: List of validated AgentEvent objects belonging to an execution trace.

    Returns:
        nx.DiGraph: A NetworkX directed graph where each node is an event_id containing
                    the full AgentEvent object, and directed edges represent parent -> child
                    execution relationships.

    Raises:
        GraphBuildError: If an event references a missing parent_event_id or if graph integrity is violated.
    """
    raise NotImplementedError("build_execution_graph is not implemented yet")

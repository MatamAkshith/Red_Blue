"""Execution graph traversal module — deterministic graph navigation utilities."""

from __future__ import annotations

import networkx as nx
from .models import GraphPath, GraphValidationError


def get_root_events(graph: nx.DiGraph) -> list[str]:
    """Retrieve all root event IDs (nodes with in-degree 0) in the execution graph.

    Args:
        graph: The execution graph (nx.DiGraph).

    Returns:
        list[str]: Sorted list of event_id strings corresponding to root events.
    """
    roots = [node for node, in_deg in graph.in_degree() if in_deg == 0]
    return sorted(roots)


def get_leaf_events(graph: nx.DiGraph) -> list[str]:
    """Retrieve all leaf event IDs (nodes with out-degree 0) in the execution graph.

    Args:
        graph: The execution graph (nx.DiGraph).

    Returns:
        list[str]: Sorted list of event_id strings corresponding to leaf events.
    """
    leaves = [node for node, out_deg in graph.out_degree() if out_deg == 0]
    return sorted(leaves)


def get_ancestors(graph: nx.DiGraph, event_id: str) -> list[str]:
    """Retrieve all ancestor event IDs for a specified target event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        event_id: Target event ID.

    Returns:
        list[str]: Sorted list of ancestor event_id strings leading up to the target event.

    Raises:
        GraphValidationError: If event_id does not exist in the graph.
    """
    if not graph.has_node(event_id):
        raise GraphValidationError(f"Event node '{event_id}' does not exist in execution graph.")
    ancestors = nx.ancestors(graph, event_id)
    return sorted(list(ancestors))


def get_descendants(graph: nx.DiGraph, event_id: str) -> list[str]:
    """Retrieve all descendant event IDs stemming from a specified event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        event_id: Source event ID.

    Returns:
        list[str]: Sorted list of descendant event_id strings spawned by the source event.

    Raises:
        GraphValidationError: If event_id does not exist in the graph.
    """
    if not graph.has_node(event_id):
        raise GraphValidationError(f"Event node '{event_id}' does not exist in execution graph.")
    descendants = nx.descendants(graph, event_id)
    return sorted(list(descendants))


def get_execution_path(graph: nx.DiGraph, source: str, target: str) -> GraphPath:
    """Retrieve the directed execution path from a source event ID to a target event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        source: Starting event ID.
        target: Target event ID.

    Returns:
        GraphPath: List of event_id strings representing the path from source to target.

    Raises:
        GraphValidationError: If source or target node does not exist, or if no directed path exists between them.
    """
    if not graph.has_node(source):
        raise GraphValidationError(f"Source event node '{source}' does not exist in execution graph.")
    if not graph.has_node(target):
        raise GraphValidationError(f"Target event node '{target}' does not exist in execution graph.")

    try:
        path = nx.shortest_path(graph, source=source, target=target)
        return list(path)
    except nx.NetworkXNoPath as exc:
        raise GraphValidationError(f"No execution path exists from '{source}' to '{target}'.") from exc

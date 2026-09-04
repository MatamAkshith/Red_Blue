"""Execution graph traversal module — contract definitions."""

from __future__ import annotations

import networkx as nx
from app.graph.models import GraphPath, GraphValidationError


def get_root_events(graph: nx.DiGraph) -> list[str]:
    """Retrieve all root event IDs (nodes with in-degree 0) in the execution graph.

    Args:
        graph: The execution graph (nx.DiGraph).

    Returns:
        list[str]: List of event_id strings corresponding to root events.
    """
    raise NotImplementedError("get_root_events is not implemented yet")


def get_leaf_events(graph: nx.DiGraph) -> list[str]:
    """Retrieve all leaf event IDs (nodes with out-degree 0) in the execution graph.

    Args:
        graph: The execution graph (nx.DiGraph).

    Returns:
        list[str]: List of event_id strings corresponding to leaf events.
    """
    raise NotImplementedError("get_leaf_events is not implemented yet")


def get_ancestors(graph: nx.DiGraph, event_id: str) -> list[str]:
    """Retrieve all ancestor event IDs for a specified target event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        event_id: Target event ID.

    Returns:
        list[str]: List of ancestor event_id strings leading up to the target event.
    """
    raise NotImplementedError("get_ancestors is not implemented yet")


def get_descendants(graph: nx.DiGraph, event_id: str) -> list[str]:
    """Retrieve all descendant event IDs stemming from a specified event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        event_id: Source event ID.

    Returns:
        list[str]: List of descendant event_id strings spawned by the source event.
    """
    raise NotImplementedError("get_descendants is not implemented yet")


def get_execution_path(graph: nx.DiGraph, source: str, target: str) -> GraphPath:
    """Retrieve the directed execution path from a source event ID to a target event ID.

    Args:
        graph: The execution graph (nx.DiGraph).
        source: Starting event ID.
        target: Target event ID.

    Returns:
        GraphPath: List of event_id strings representing the path from source to target.
    """
    raise NotImplementedError("get_execution_path is not implemented yet")

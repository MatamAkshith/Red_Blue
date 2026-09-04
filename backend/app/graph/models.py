"""Execution Graph Models, Exceptions, and Invariants.

CORE GRAPH INVARIANTS:
1. Invariant 1: One event = one node (Node identity = `event_id`).
   Every validated AgentEvent in an execution trace corresponds to exactly one node in the graph, keyed by its unique event_id.
2. Invariant 2: Stable identity.
   The event_id is the immutable identifier for nodes across all graph operations, lookups, and traversals.
3. Invariant 3: Parent integrity (no fabricated parents; missing parent = error).
   If an event specifies a parent_event_id, that parent must exist within the trace. Referencing an unknown or missing parent raises a GraphBuildError. No parent-child links may be invented.
4. Invariant 4: Real relationships only (Edge = `parent_event_id` -> `event_id`).
   Directed edges exclusively represent true causal execution relationships where a parent event spawned or preceded a child event.
5. Invariant 5: Original AgentEvent preservation (the intact event is stored as node data).
   The complete, unaltered AgentEvent model instance is stored directly in the graph node attributes (e.g., node_data['event']).
6. Invariant 6: Deterministic execution.
   Given the same sequence of AgentEvents, graph construction produces an identical graph topology and node representation every time.
7. Invariant 7: No security semantics (the graph does not decide maliciousness/risk).
   The Execution Graph is a pure, structural execution representation. It contains no vulnerability scores, detection logic, or risk assessments.
"""

from __future__ import annotations

from typing import List
from app.events.schemas import AgentEvent

# Lightweight type aliases
GraphPath = List[str]


class GraphBuildError(Exception):
    """Raised when an error occurs during execution graph construction (e.g. dangling parent_event_id)."""
    pass


class GraphValidationError(Exception):
    """Raised when an execution graph fails structural integrity or validation checks."""
    pass

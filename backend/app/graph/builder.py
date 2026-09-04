"""Execution graph builder — the primary source of execution truth.

STUB: not yet implemented. Will build a NetworkX DiGraph from a session's
AgentEvents (Document -> Retrieval -> Agent Decision -> Tool Call ->
Resource -> Downstream Action), keyed on event_id/parent_event_id.
"""

from __future__ import annotations

from app.events.schemas import AgentEvent


def build_execution_graph(events: list[AgentEvent]):
    raise NotImplementedError("execution graph builder: not yet implemented")

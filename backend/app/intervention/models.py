"""Intervention candidates and their deterministic application to a trace."""

from __future__ import annotations

from enum import Enum

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from backend.app.events.schemas import AgentEvent
from backend.app.graph import get_descendants


class InterventionType(str, Enum):
    BLOCK_EXTERNAL_DESTINATION = "BLOCK_EXTERNAL_DESTINATION"
    BLOCK_RESOURCE = "BLOCK_RESOURCE"
    BLOCK_TOOL = "BLOCK_TOOL"
    KILL_AGENT = "KILL_AGENT"


# Operational disruption cost. Lower = less disruptive = preferred when two
# candidates are equally effective.
INTERVENTION_COST: dict[InterventionType, int] = {
    InterventionType.BLOCK_EXTERNAL_DESTINATION: 1,
    InterventionType.BLOCK_RESOURCE: 2,
    InterventionType.BLOCK_TOOL: 3,
    InterventionType.KILL_AGENT: 10,
}


class Intervention(BaseModel):
    model_config = ConfigDict(frozen=True)

    intervention_type: InterventionType
    value: str
    cost: int = 0
    description: str = ""


def build_intervention(intervention_type: InterventionType, value: str) -> Intervention:
    return Intervention(
        intervention_type=intervention_type,
        value=value,
        cost=INTERVENTION_COST[intervention_type],
        description=f"{intervention_type.value} {value}",
    )


def _event_blocked(event: AgentEvent, intervention: Intervention) -> bool:
    t = intervention.intervention_type
    v = intervention.value
    if t is InterventionType.BLOCK_EXTERNAL_DESTINATION:
        return event.target == v
    if t is InterventionType.BLOCK_RESOURCE:
        return event.resource == v
    if t is InterventionType.BLOCK_TOOL:
        return event.target == v
    if t is InterventionType.KILL_AGENT:
        return event.agent_id == v
    return False


def apply_intervention(
    events: list[AgentEvent], graph: nx.DiGraph, intervention: Intervention
) -> list[AgentEvent]:
    """Return the trace as it would have executed under the intervention.

    A blocked event never happens, so nothing downstream of it happens
    either -- descendants are removed using the authoritative P1.1
    traversal, not recomputed here.
    """

    blocked: set[str] = set()
    for event in events:
        if _event_blocked(event, intervention):
            blocked.add(event.event_id)
            if graph.has_node(event.event_id):
                blocked.update(get_descendants(graph, event.event_id))

    return [event for event in events if event.event_id not in blocked]

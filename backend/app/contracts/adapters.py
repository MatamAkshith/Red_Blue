"""P1 -> P2 adapter compatibility wrapper.

Re-exports the authoritative P1.4 adapter implementation from backend.app.adapter.
"""

from __future__ import annotations

from typing import Any, Collection, Sequence

import networkx as nx
from backend.app.adapter import build_incident_analysis as authoritative_build_incident_analysis
from backend.app.aegis.models import ImpactResult
from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.detection.models import DetectionFinding
from backend.app.events.schemas import AgentEvent
from backend.app.graph import build_execution_graph


def build_incident_analysis(
    arg1: str | nx.DiGraph | Sequence[AgentEvent],
    arg2: Sequence[AgentEvent] | Collection[DetectionFinding],
    arg3: Collection[DetectionFinding] | Collection[ImpactResult],
    arg4: Collection[ImpactResult] | None = None,
) -> IncidentAnalysis:
    """Compatibility wrapper for build_incident_analysis.

    Supports both signatures:
    - (graph, findings, impacts) -> authoritative P1.4 call
    - (incident_id, events, findings, impacts) -> legacy/scaffold call
    """
    if isinstance(arg1, nx.DiGraph):
        return authoritative_build_incident_analysis(arg1, arg2, arg3)  # type: ignore

    if isinstance(arg1, str) and arg4 is not None:
        # arg1: incident_id, arg2: events, arg3: findings, arg4: impacts
        events = list(arg2)  # type: ignore
        findings = list(arg3)  # type: ignore
        impacts = list(arg4)
        graph = build_execution_graph(events) if events else nx.DiGraph()
        result = authoritative_build_incident_analysis(graph, findings, impacts)
        return result.model_copy(update={"incident_id": arg1})

    if isinstance(arg1, (list, tuple)):
        # arg1: events, arg2: findings, arg3: impacts
        events = list(arg1)
        findings = list(arg2)  # type: ignore
        impacts = list(arg3)  # type: ignore
        graph = build_execution_graph(events) if events else nx.DiGraph()
        return authoritative_build_incident_analysis(graph, findings, impacts)

    raise ValueError(f"Invalid arguments to build_incident_analysis: {arg1=}, {arg2=}")

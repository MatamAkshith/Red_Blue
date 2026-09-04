"""Deterministic what-if simulation.

Applies a candidate intervention to the trace and re-runs the authoritative
P1.1 -> P1.2 -> P1.3 engines. No separate simulation model, no heuristics:
"what would have happened" is computed by the same engines that decide what
did happen.
"""

from __future__ import annotations

from typing import Collection

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from app.aegis.engine import ImpactEngine
from app.aegis.models import ImpactResult
from app.contracts.incident_analysis import SensitiveResource
from app.detection import DetectionEngine, DetectionFinding, DetectorType
from app.events.schemas import AgentEvent
from app.graph import build_execution_graph
from app.intervention.models import Intervention, apply_intervention


class SimulationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    intervention: Intervention
    residual_finding_ids: tuple[str, ...] = Field(default_factory=tuple)
    residual_detector_types: tuple[str, ...] = Field(default_factory=tuple)
    residual_external_destinations: tuple[str, ...] = Field(default_factory=tuple)
    residual_sensitive_resources: tuple[str, ...] = Field(default_factory=tuple)
    removed_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    exfiltration_path_severed: bool = False


def _analyze(
    events: list[AgentEvent], registry: Collection[SensitiveResource]
) -> tuple[list[DetectionFinding], tuple[ImpactResult, ...]]:
    if not events:
        return [], ()
    graph = build_execution_graph(events)
    findings = DetectionEngine().run(graph)
    impacts = ImpactEngine().analyze(graph, findings, known_sensitive_resources=registry)
    return findings, impacts


def simulate(
    events: list[AgentEvent],
    graph: nx.DiGraph,
    intervention: Intervention,
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
) -> SimulationResult:
    surviving = apply_intervention(events, graph, intervention)
    removed = tuple(
        e.event_id for e in events if e.event_id not in {s.event_id for s in surviving}
    )

    findings, impacts = _analyze(surviving, known_sensitive_resources)

    destinations: list[str] = []
    resources: list[str] = []
    for impact in impacts:
        destinations.extend(impact.reachable_external_destinations)
        resources.extend(r.resource for r in impact.reachable_sensitive_resources)

    detector_types = tuple(
        sorted({str(getattr(f.detector_type, "value", f.detector_type)) for f in findings})
    )
    severed = DetectorType.DATA_EXFILTRATION.value not in detector_types

    return SimulationResult(
        intervention=intervention,
        residual_finding_ids=tuple(f.finding_id for f in findings),
        residual_detector_types=detector_types,
        residual_external_destinations=tuple(sorted(set(destinations))),
        residual_sensitive_resources=tuple(sorted(set(resources))),
        removed_event_ids=removed,
        exfiltration_path_severed=severed,
    )

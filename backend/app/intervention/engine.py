"""Minimum effective intervention selection.

Candidates are derived only from facts AEGIS actually established, then
each is evaluated by deterministic what-if simulation. The cheapest
candidate that severs the exfiltration path wins. No LLM, no scoring
heuristics.
"""

from __future__ import annotations

from typing import Collection

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from backend.app.aegis.models import ImpactResult
from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.detection import DetectionFinding, DetectorType
from backend.app.events.schemas import AgentEvent
from backend.app.intervention.models import (
    Intervention,
    InterventionType,
    build_intervention,
)
from backend.app.whatif.simulator import SimulationResult, simulate


class InterventionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    selected: Intervention | None = None
    rationale: str = ""
    evaluated: tuple[SimulationResult, ...] = Field(default_factory=tuple)


def build_candidates(impacts: Collection[ImpactResult]) -> tuple[Intervention, ...]:
    candidates: list[Intervention] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: InterventionType, value: str) -> None:
        key = (kind.value, value)
        if value and key not in seen:
            seen.add(key)
            candidates.append(build_intervention(kind, value))

    for impact in impacts:
        for destination in impact.reachable_external_destinations:
            add(InterventionType.BLOCK_EXTERNAL_DESTINATION, destination)
        for resource in impact.reachable_sensitive_resources:
            add(InterventionType.BLOCK_RESOURCE, resource.resource)
        for tool in impact.affected_tools:
            add(InterventionType.BLOCK_TOOL, tool)
        for agent in impact.affected_agents:
            add(InterventionType.KILL_AGENT, agent)

    return tuple(sorted(candidates, key=lambda c: (c.cost, c.intervention_type.value, c.value)))


def select_minimum_effective(
    events: list[AgentEvent],
    graph: nx.DiGraph,
    impacts: Collection[ImpactResult],
    findings: Collection[DetectionFinding],
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
) -> InterventionDecision:
    # An intervention is only warranted if the dangerous path exists in the
    # first place. Without this, every candidate "severs" an exfiltration
    # path that was never there.
    baseline_types = {
        str(getattr(f.detector_type, "value", f.detector_type)) for f in findings
    }
    if DetectorType.DATA_EXFILTRATION.value not in baseline_types:
        return InterventionDecision(
            selected=None,
            rationale="No exfiltration path detected; no intervention required.",
        )

    candidates = build_candidates(impacts)
    evaluated: list[SimulationResult] = []

    for candidate in candidates:
        result = simulate(
            events, graph, candidate, known_sensitive_resources=known_sensitive_resources
        )
        evaluated.append(result)

    effective = [r for r in evaluated if r.exfiltration_path_severed]
    if not effective:
        return InterventionDecision(
            selected=None,
            rationale="No candidate intervention severed the exfiltration path.",
            evaluated=tuple(evaluated),
        )

    # Candidates were already ordered cheapest-first; the first effective one
    # is the minimum effective intervention.
    best = effective[0]
    return InterventionDecision(
        selected=best.intervention,
        rationale=(
            f"{best.intervention.description} severs the exfiltration path "
            f"at cost {best.intervention.cost}, removing "
            f"{len(best.removed_event_ids)} event(s)."
        ),
        evaluated=tuple(evaluated),
    )

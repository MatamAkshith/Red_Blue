"""P1.4 -- deterministic orchestration.

    events -> graph -> detection -> impact -> what-if -> intervention
           -> verification -> (optional) investigation

Wiring only. Every security decision is made by the engine that owns it;
this module contains no detection, reachability, scoring, or policy logic
of its own.
"""

from __future__ import annotations

from typing import Collection

from pydantic import BaseModel, ConfigDict, Field

from backend.app.aegis.engine import ImpactEngine
from backend.app.aegis.models import ImpactResult
from backend.app.chimera.replay import VerificationResult, replay
from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.detection import DetectionEngine, DetectionFinding
from backend.app.events.schemas import AgentEvent
from backend.app.graph import build_execution_graph
from backend.app.intervention.engine import InterventionDecision, select_minimum_effective


class IncidentReport(BaseModel):
    """Single structured result for the frontend."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    event_ids: tuple[str, ...] = Field(default_factory=tuple)
    findings: tuple[DetectionFinding, ...] = Field(default_factory=tuple)
    impacts: tuple[ImpactResult, ...] = Field(default_factory=tuple)
    intervention: InterventionDecision = Field(default_factory=InterventionDecision)
    verification: VerificationResult = Field(default_factory=VerificationResult)


def run_pipeline(
    events: list[AgentEvent],
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
) -> IncidentReport:
    graph = build_execution_graph(events)
    findings = DetectionEngine().run(graph)
    impacts = ImpactEngine().analyze(
        graph, findings, known_sensitive_resources=known_sensitive_resources
    )
    decision = select_minimum_effective(
        events,
        graph,
        impacts,
        findings,
        known_sensitive_resources=known_sensitive_resources,
    )
    verification = replay(
        events,
        graph,
        decision.selected,
        known_sensitive_resources=known_sensitive_resources,
    )

    return IncidentReport(
        session_id=events[0].session_id if events else "",
        event_ids=tuple(e.event_id for e in events),
        findings=tuple(findings),
        impacts=tuple(impacts),
        intervention=decision,
        verification=verification,
    )

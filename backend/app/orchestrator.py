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

from app.aegis.engine import ImpactEngine
from app.aegis.models import ImpactResult
from app.chimera.replay import VerificationResult, replay
from app.contracts.adapters import build_incident_analysis
from app.contracts.incident_analysis import IncidentAnalysis, SensitiveResource
from app.detection import DetectionEngine, DetectionFinding
from app.events.schemas import AgentEvent
from app.graph import build_execution_graph
from app.memory import (
    FailurePatternStore,
    PatternProvenance,
    StoredPattern,
    compute_signature,
)
from app.intervention.engine import InterventionDecision, select_minimum_effective
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import Investigation


class IncidentReport(BaseModel):
    """Single structured result for the frontend."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    event_ids: tuple[str, ...] = Field(default_factory=tuple)
    findings: tuple[DetectionFinding, ...] = Field(default_factory=tuple)
    impacts: tuple[ImpactResult, ...] = Field(default_factory=tuple)
    incident: IncidentAnalysis | None = None
    investigation: Investigation | None = None
    pattern_signature: str = ""
    recalled_pattern: StoredPattern | None = None
    intervention: InterventionDecision = Field(default_factory=InterventionDecision)
    verification: VerificationResult = Field(default_factory=VerificationResult)


def run_pipeline(
    events: list[AgentEvent],
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
    incident_id: str = "INC-1",
    explain: bool = False,
    pattern_store: FailurePatternStore | None = None,
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

    incident = build_incident_analysis(incident_id, events, findings, impacts)
    # Explanation is opt-in: P1 is deterministic and offline, P2 calls out to
    # Featherless. Callers ask for a narrative explicitly.
    # P2 explains P1's facts; it never produces or overrides them.
    investigation = investigate(incident) if explain and findings else None

    # Failure-pattern memory. The signature comes from P1 facts only, so
    # recall works offline; Featherless is only needed to author a new
    # pattern, never to match a known one.
    signature = compute_signature(findings, impacts) if findings else ""
    recalled: StoredPattern | None = None
    if pattern_store is not None and signature:
        recalled = pattern_store.recall(signature)
        candidate = investigation.failure_pattern_candidate if investigation else None
        if candidate is not None:
            recalled = pattern_store.remember(
                signature,
                candidate,
                PatternProvenance(
                    incident_id=incident_id,
                    session_id=incident.session_id,
                    finding_ids=tuple(f.finding_id for f in findings),
                    event_ids=tuple(e.event_id for e in events),
                ),
            )

    return IncidentReport(
        pattern_signature=signature,
        recalled_pattern=recalled,
        incident=incident,
        investigation=investigation,
        session_id=events[0].session_id if events else "",
        event_ids=tuple(e.event_id for e in events),
        findings=tuple(findings),
        impacts=tuple(impacts),
        intervention=decision,
        verification=verification,
    )

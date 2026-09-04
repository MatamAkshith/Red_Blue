"""P1.4 -- deterministic orchestration & investigation pipeline.

    events -> graph -> detection -> impact -> adapter -> investigation
           -> what-if -> intervention -> verification

Wiring only. Every security decision is made by the engine that owns it;
this module contains no detection, reachability, scoring, or policy logic
of its own.
"""

from __future__ import annotations

from typing import Collection

from pydantic import BaseModel, ConfigDict, Field

from .adapter import AdapterValidationError, build_incident_analysis
from .aegis.engine import ImpactEngine
from .aegis.models import ImpactResult
from .chimera.replay import VerificationResult, replay
from .contracts.incident_analysis import IncidentAnalysis, SensitiveResource
from .detection import DetectionEngine, DetectionFinding
from .events.schemas import AgentEvent
from .graph import build_execution_graph
from .intervention.engine import InterventionDecision, select_minimum_effective
from .understand.evidence.extractor import build_prompt_evidence
from .understand.fallback.deterministic import fallback_investigation
from .understand.featherless.client import FeatherlessError
from .understand.investigation.investigator import investigate
from .understand.investigation.schemas import Investigation


class IncidentReport(BaseModel):
    """Single structured result for frontend and API pipeline consumers."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    event_ids: tuple[str, ...] = Field(default_factory=tuple)
    findings: tuple[DetectionFinding, ...] = Field(default_factory=tuple)
    impacts: tuple[ImpactResult, ...] = Field(default_factory=tuple)
    incident_analysis: IncidentAnalysis | None = None
    investigation: Investigation | None = None
    intervention: InterventionDecision = Field(default_factory=InterventionDecision)
    verification: VerificationResult = Field(default_factory=VerificationResult)


def run_pipeline(
    events: list[AgentEvent],
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
    include_investigation: bool = True,
) -> IncidentReport:
    """Execute full Blackbox pipeline from raw events to investigation report.

    Args:
        events: List of normalized AgentEvent objects.
        known_sensitive_resources: Registry of classified sensitive resources.
        include_investigation: Whether to trigger P2.2 investigation step.

    Returns:
        IncidentReport: Structured report containing findings, impact, IncidentAnalysis,
                        Investigation, intervention, and defense verification.
    """
    if not events:
        return IncidentReport(session_id="")

    # 1. P1.1 Execution Graph
    graph = build_execution_graph(events)

    # 2. P1.2 Detection Engine
    findings = DetectionEngine().run(graph)

    # 3. P1.3 AEGIS Impact Analysis
    impacts = ImpactEngine().analyze(
        graph, findings, known_sensitive_resources=known_sensitive_resources
    )

    # 4. P1.4 Adapter: P1 facts -> IncidentAnalysis contract
    incident_analysis: IncidentAnalysis | None = None
    try:
        incident_analysis = build_incident_analysis(graph, findings, impacts)
    except AdapterValidationError:
        incident_analysis = None

    # 5. P2.2 Investigation Execution (with Graceful Fallback)
    investigation_result: Investigation | None = None
    if include_investigation and incident_analysis is not None:
        try:
            investigation_result = investigate(incident_analysis)
        except (FeatherlessError, Exception):
            try:
                evidence_pkg = build_prompt_evidence(incident_analysis)
                investigation_result = fallback_investigation(evidence_pkg)
            except Exception:
                investigation_result = None

    # 6. P1.6 Intervention Selection (What-If simulation under the hood)
    decision = select_minimum_effective(
        events,
        graph,
        impacts,
        findings,
        known_sensitive_resources=known_sensitive_resources,
    )

    # 7. CHIMERA Verification (Re-attack simulation)
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
        incident_analysis=incident_analysis,
        investigation=investigation_result,
        intervention=decision,
        verification=verification,
    )


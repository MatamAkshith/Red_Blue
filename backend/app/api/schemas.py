from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field

from backend.app.chimera.replay import VerificationResult
from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.detection.models import DetectionFinding
from backend.app.events.schemas import AgentEvent
from backend.app.intervention.engine import InterventionDecision
from backend.app.memory.patterns import StoredPattern
from backend.app.understand.investigation.schemas import Investigation


class IncidentInfo(BaseModel):
    """Core incident identification and status summary."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    session_id: str
    agent_id: str
    severity: str
    status: str = "ANALYZED"


class SimulateRequest(BaseModel):
    """Request payload for counterfactual what-if simulation."""

    events: list[AgentEvent]
    intervention_type: str = "BLOCK_EXTERNAL_DESTINATION"
    target_event_id: str | None = None
    target_destination: str | None = None


class DefendRequest(BaseModel):
    """Request payload for applying defense and running CHIMERA verification."""

    events: list[AgentEvent]
    intervention_decision: InterventionDecision | None = None


class IncidentResponse(BaseModel):
    """Unified master payload exposing the complete BLACKBOX security state to the frontend."""

    incident_info: IncidentInfo | None = None
    events: list[AgentEvent] = Field(default_factory=list)
    findings: list[DetectionFinding] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    investigation: Investigation | None = None
    blast_radius: dict[str, Any] | None = None
    what_if_result: dict[str, Any] | None = None
    intervention: InterventionDecision | None = None
    defense_result: dict[str, Any] | None = None
    chimera_verification: VerificationResult | None = None
    memory_pattern: StoredPattern | None = None

    # Pipeline compatibility fields (for backwards-compatibility & existing API tests)
    incident_analysis: IncidentAnalysis | None = None
    impacts: list[Any] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    pattern_signature: str = ""
    recalled_pattern: StoredPattern | None = None

    @computed_field
    @property
    def incident(self) -> IncidentAnalysis | None:
        """Alias returning incident_analysis for legacy frontend contract parity."""
        return self.incident_analysis

    @computed_field
    @property
    def verification(self) -> VerificationResult | None:
        """Alias returning chimera_verification for verification parity."""
        return self.chimera_verification


def build_incident_response(
    report: Any, raw_events: list[AgentEvent]
) -> IncidentResponse:
    """Aggregates deterministic pipeline report outputs into a unified IncidentResponse payload."""
    inc_analysis = getattr(report, "incident_analysis", None)

    inc_info = None
    attack_path: list[str] = []
    blast_rad_dict: dict[str, Any] | None = None

    if inc_analysis is not None:
        inc_info = IncidentInfo(
            incident_id=getattr(inc_analysis, "incident_id", "INC-1"),
            session_id=getattr(inc_analysis, "session_id", ""),
            agent_id=getattr(inc_analysis, "agent_id", ""),
            severity=(
                inc_analysis.severity.value
                if hasattr(inc_analysis.severity, "value")
                else str(inc_analysis.severity)
            ),
            status="ANALYZED",
        )
        attack_path = list(getattr(inc_analysis, "attack_path", ()))
        br = getattr(inc_analysis, "blast_radius", None)
        if br is not None:
            blast_rad_dict = br.model_dump() if hasattr(br, "model_dump") else dict(br)

    intervention_dec = getattr(report, "intervention", None)
    what_if: dict[str, Any] | None = None
    if intervention_dec and getattr(intervention_dec, "evaluated", None):
        first_eval = intervention_dec.evaluated[0]
        what_if = (
            first_eval.model_dump()
            if hasattr(first_eval, "model_dump")
            else dict(first_eval)
        )

    verif = getattr(report, "verification", None)
    defense_res: dict[str, Any] | None = None
    if verif is not None:
        blocked = getattr(verif, "blocked_event_ids", ())
        defense_res = {
            "defense_verified": getattr(verif, "defense_verified", False),
            "attack_before": getattr(verif, "attack_before", ""),
            "attack_after": getattr(verif, "attack_after", ""),
            "blocked_events": list(blocked),
        }

    recalled = getattr(report, "recalled_pattern", None)

    return IncidentResponse(
        incident_info=inc_info,
        events=raw_events,
        findings=list(getattr(report, "findings", [])),
        attack_path=attack_path,
        investigation=getattr(report, "investigation", None),
        blast_radius=blast_rad_dict,
        what_if_result=what_if,
        intervention=intervention_dec,
        defense_result=defense_res,
        chimera_verification=verif,
        memory_pattern=recalled,
        incident_analysis=inc_analysis,
        impacts=list(getattr(report, "impacts", [])),
        event_ids=list(
            getattr(report, "event_ids", [e.event_id for e in raw_events])
        ),
        pattern_signature=getattr(report, "pattern_signature", ""),
        recalled_pattern=recalled,
    )

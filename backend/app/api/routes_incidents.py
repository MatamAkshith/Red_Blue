"""POST /incidents/analyze -- the full deterministic pipeline over a trace.

Thin HTTP layer over backend.app.orchestrator.run_pipeline; contains no security
logic of its own.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.api.schemas import (
    DefendRequest,
    IncidentResponse,
    SimulateRequest,
    build_incident_response,
)
from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.core.config import get_settings
from backend.app.events.schemas import AgentEvent
from backend.app.memory import FailurePatternStore
from backend.app.orchestrator import run_pipeline
from backend.app.scenarios import SENSITIVE_REGISTRY, build_exfiltration_events

router = APIRouter(prefix="/incidents", tags=["incidents"])

_pattern_store: FailurePatternStore | None = None


def get_pattern_store() -> FailurePatternStore:
    """Lazily-built process-wide pattern memory (overridable in tests)."""
    global _pattern_store
    if _pattern_store is None:
        _pattern_store = FailurePatternStore(get_settings().db_path)
    return _pattern_store


class AnalyzeRequest(BaseModel):
    events: list[AgentEvent]
    known_sensitive_resources: list[SensitiveResource] = Field(default_factory=list)
    incident_id: str = "INC-1"
    explain: bool = True


@router.post("/analyze", response_model=IncidentResponse)
def analyze_incident(request: AnalyzeRequest) -> IncidentResponse:
    report = run_pipeline(
        request.events,
        known_sensitive_resources=request.known_sensitive_resources,
        include_investigation=request.explain,
        pattern_store=get_pattern_store(),
    )
    return build_incident_response(report, request.events)


class DemoScenario(BaseModel):
    events: list[AgentEvent]
    known_sensitive_resources: list[SensitiveResource]


@router.get("/demo-scenario", response_model=DemoScenario)
def demo_scenario() -> DemoScenario:
    """The controlled demo trace, so clients never fabricate events."""
    return DemoScenario(
        events=build_exfiltration_events(),
        known_sensitive_resources=list(SENSITIVE_REGISTRY),
    )


@router.post("/{incident_id}/simulate")
def simulate_intervention(
    incident_id: str, request: SimulateRequest
) -> dict[str, Any]:
    """Runs counterfactual What-If simulation for a proposed intervention."""
    if not request.events:
        raise HTTPException(status_code=400, detail="No events provided for simulation")

    report = run_pipeline(
        request.events,
        include_investigation=False,
        pattern_store=get_pattern_store(),
    )

    decision = report.intervention
    selected = decision.selected if decision else None

    return {
        "incident_id": incident_id,
        "intervention_type": request.intervention_type,
        "target_event_id": request.target_event_id,
        "target_destination": request.target_destination,
        "selected_intervention": selected,
        "evaluated_simulations": [
            sim.model_dump() for sim in (decision.evaluated if decision else [])
        ],
        "status": "SIMULATED",
    }


@router.post("/{incident_id}/defend")
def defend_incident(incident_id: str, request: DefendRequest) -> dict[str, Any]:
    """Applies defense intervention and runs CHIMERA re-attack verification."""
    if not request.events:
        raise HTTPException(
            status_code=400, detail="No events provided for defense verification"
        )

    report = run_pipeline(
        request.events,
        include_investigation=False,
        pattern_store=get_pattern_store(),
    )

    if report.intervention and report.intervention.selected:
        from backend.app.target.guard import get_global_enforcement_guard
        get_global_enforcement_guard().install(report.intervention.selected)

    verif = report.verification
    return {
        "incident_id": incident_id,
        "defense_verified": verif.defense_verified if verif else False,
        "attack_before": verif.attack_before if verif else "UNKNOWN",
        "attack_after": verif.attack_after if verif else "UNKNOWN",
        "blocked_event_ids": list(verif.blocked_event_ids) if verif else [],
        "intervention_applied": report.intervention.selected
        if report.intervention
        else None,
        "status": "DEFENDED",
    }

"""POST /incidents/analyze -- the full deterministic pipeline over a trace.

Thin HTTP layer over app.orchestrator.run_pipeline; contains no security
logic of its own.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.contracts.incident_analysis import SensitiveResource
from app.events.schemas import AgentEvent
from app.orchestrator import IncidentReport, run_pipeline

router = APIRouter(prefix="/incidents", tags=["incidents"])


class AnalyzeRequest(BaseModel):
    events: list[AgentEvent]
    known_sensitive_resources: list[SensitiveResource] = Field(default_factory=list)
    incident_id: str = "INC-1"
    explain: bool = True


@router.post("/analyze", response_model=IncidentReport)
def analyze_incident(request: AnalyzeRequest) -> IncidentReport:
    return run_pipeline(
        request.events,
        known_sensitive_resources=request.known_sensitive_resources,
        incident_id=request.incident_id,
        explain=request.explain,
    )

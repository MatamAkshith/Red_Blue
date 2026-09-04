"""POST /incidents/analyze -- the full deterministic pipeline over a trace.

Thin HTTP layer over backend.app.orchestrator.run_pipeline; contains no security
logic of its own.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.core.config import get_settings
from backend.app.events.schemas import AgentEvent
from backend.app.memory import FailurePatternStore
from backend.app.orchestrator import IncidentReport, run_pipeline

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


@router.post("/analyze", response_model=IncidentReport)
def analyze_incident(request: AnalyzeRequest) -> IncidentReport:
    return run_pipeline(
        request.events,
        known_sensitive_resources=request.known_sensitive_resources,
        include_investigation=request.explain,
        pattern_store=get_pattern_store(),
    )


class DemoScenario(BaseModel):
    events: list[AgentEvent]
    known_sensitive_resources: list[SensitiveResource]


@router.get("/demo-scenario", response_model=DemoScenario)
def demo_scenario() -> DemoScenario:
    """The controlled demo trace, so clients never fabricate events."""
    from backend.app.scenarios import SENSITIVE_REGISTRY, build_exfiltration_events

    return DemoScenario(
        events=build_exfiltration_events(),
        known_sensitive_resources=list(SENSITIVE_REGISTRY),
    )

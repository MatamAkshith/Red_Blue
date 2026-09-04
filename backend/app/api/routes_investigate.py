"""POST /investigate — the FastAPI-facing edge of the P2 pipeline.

This route is a thin translation layer only: FastAPI validates the
IncidentAnalysis request body and serializes the Investigation response.
All actual orchestration lives in app.understand.investigation.investigator
(investigate()), which has no FastAPI dependency and is independently
testable without this router.

    P1 Incident -> Evidence Extractor -> Investigator -> FeatherlessClient
    -> InvestigationResult -> (here) -> HTTP response
"""

from __future__ import annotations

from fastapi import APIRouter

from app.contracts.incident_analysis import IncidentAnalysis
from app.understand.investigation.investigator import investigate
from app.understand.investigation.schemas import Investigation

router = APIRouter(prefix="/investigate", tags=["investigate"])


@router.post("", response_model=Investigation)
def investigate_incident(incident: IncidentAnalysis) -> Investigation:
    return investigate(incident)

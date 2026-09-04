"""Structured investigation contract returned by Featherless (or the
deterministic fallback in app.understand.fallback). This is the stable
schema the frontend and the rest of Blackbox depend on.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CriticalDecision(BaseModel):
    event_id: str
    explanation: str


class SupportingEvidenceItem(BaseModel):
    event_id: str
    reason: str


class Investigation(BaseModel):
    root_cause: str
    critical_decision: CriticalDecision
    attack_narrative: str
    supporting_evidence: list[SupportingEvidenceItem] = Field(default_factory=list)
    recommendation: str
    confidence: float

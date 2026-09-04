"""Structured investigation output returned by Featherless (or the
deterministic fallback in app.understand.fallback). This is the stable
contract the frontend and the rest of Blackbox depend on.

The model is NOT the security authority -- it never establishes whether an
event happened, whether a resource is reachable, or blast radius; that all
comes in as already-determined fact via the P1 -> P2 IncidentAnalysis
contract (app.contracts.incident_analysis). Its job is only to interpret
that evidence: explain why the incident happened, reconstruct the
narrative, and point at the evidence backing each claim.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CriticalDecision(BaseModel):
    event_id: str
    explanation: str


class EvidenceInterpretation(BaseModel):
    """What one piece of supplied evidence means, in the model's reading --
    never a new fact, only an interpretation of a fact it was given."""

    event_id: str
    interpretation: str


class FailurePatternCandidate(BaseModel):
    """An abstracted, reusable pattern for future detection -- the
    technology-specific incident changes, the underlying failure shape
    tends to repeat."""

    pattern_name: str
    description: str
    indicators: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    root_cause: str
    attack_narrative: str
    critical_decision: CriticalDecision
    evidence_interpretation: list[EvidenceInterpretation] = Field(default_factory=list)
    # Bounded so a malformed/hallucinating response (e.g. confidence=150)
    # is rejected by schema validation -- caught as a FeatherlessError and
    # routed to the deterministic fallback -- rather than silently accepted
    # as a plausible-looking result.
    confidence: float = Field(ge=0.0, le=1.0)
    contributing_factors: list[str] = Field(default_factory=list)
    failure_pattern_candidate: FailurePatternCandidate | None = None

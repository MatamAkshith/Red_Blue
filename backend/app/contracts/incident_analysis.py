"""The P1 -> P2 contract.

IncidentAnalysis is what the deterministic security engine (P1: execution
graph + detection + AEGIS + evidence extraction) hands to the Understand
layer (P2: Featherless investigation). It represents SECURITY EVIDENCE that
P1 has already determined to be true -- not raw application logs, and not
something P2/the LLM is asked to (re)discover.

This is the frozen contract; changes here are breaking changes for both
sides. See ../../../contracts/incident_analysis.json for the language
agnostic JSON Schema generated from this model.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from app.aegis.blast_radius import Severity
from app.events.schemas import AgentEvent


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PermissionFact(BaseModel):
    """A permission-relevant fact P1 observed, e.g. an agent attempting to
    use a privileged tool/resource, or a privilege change."""

    event_id: str
    resource: str
    permission: str
    granted: bool


class SensitiveResource(BaseModel):
    resource: str
    severity: Severity
    resource_type: str | None = None


class BlastRadius(BaseModel):
    """Mirrors the output of app.aegis.blast_radius.compute_blast_radius."""

    reachable_sensitive_resources: list[str] = Field(default_factory=list)
    reachable_external_destinations: list[str] = Field(default_factory=list)
    affected_capabilities: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class EvidenceItem(BaseModel):
    """One deterministically-tagged fact supporting the incident. `category`
    is a free string; the Understand-layer evidence extractor recognizes a
    known set (trust_boundary_crossing, privilege_change, data_movement,
    external_transmission, anomaly) for grouping and passes the rest through
    unclassified -- new categories don't break anything."""

    event_id: str
    category: str
    description: str


class IncidentAnalysis(BaseModel):
    incident_id: str
    agent_id: str
    session_id: str
    incident_type: str
    severity: IncidentSeverity
    events: list[AgentEvent] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    permissions: list[PermissionFact] = Field(default_factory=list)
    sensitive_resources: list[SensitiveResource] = Field(default_factory=list)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    evidence: list[EvidenceItem] = Field(default_factory=list)

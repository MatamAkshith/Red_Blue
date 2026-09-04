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

from pydantic import BaseModel, ConfigDict, Field

from backend.app.aegis.blast_radius import Severity
from backend.app.events.schemas import AgentEvent


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PermissionFact(BaseModel):
    """A permission-relevant fact P1 observed, e.g. an agent attempting to
    use a privileged tool/resource, or a privilege change. Frozen: a P1
    permission fact must not be mutable once P2 receives it."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    resource: str
    permission: str
    granted: bool


class SensitiveResource(BaseModel):
    """Frozen: a P1 sensitive-resource fact must not be mutable once P2
    receives it."""

    model_config = ConfigDict(frozen=True)

    resource: str
    severity: Severity
    resource_type: str | None = None


class BlastRadius(BaseModel):
    """Mirrors the output of app.aegis.blast_radius.compute_blast_radius.
    Frozen: blast radius is a P1-computed security fact, never something P2
    or an LLM recalculates or edits in place."""

    model_config = ConfigDict(frozen=True)

    reachable_sensitive_resources: tuple[str, ...] = Field(default_factory=tuple)
    reachable_external_destinations: tuple[str, ...] = Field(default_factory=tuple)
    affected_capabilities: tuple[str, ...] = Field(default_factory=tuple)
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
    """Frozen: once P1 hands an incident to P2, its security facts --
    severity, attack_path, permissions, sensitive_resources, blast_radius --
    must not be reassignable or mutable in place. P2 (including Featherless,
    whose output has no field for any of these -- see
    app.understand.investigation.schemas.Investigation) only ever reads
    this object; nothing in the pipeline writes back to it."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    agent_id: str
    session_id: str
    incident_type: str
    severity: IncidentSeverity
    events: list[AgentEvent] = Field(default_factory=list)
    attack_path: tuple[str, ...] = Field(default_factory=tuple)
    permissions: tuple[PermissionFact, ...] = Field(default_factory=tuple)
    sensitive_resources: tuple[SensitiveResource, ...] = Field(default_factory=tuple)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    evidence: list[EvidenceItem] = Field(default_factory=list)

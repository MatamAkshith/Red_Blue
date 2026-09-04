"""P1.3 AEGIS impact contract.

P1.3 receives the authoritative P1.1 ``networkx.DiGraph`` and a P1.2
``DetectionFinding``.  Its later analyzer will prove downstream impact from
real graph edges; it does not detect attacks or construct another graph.

``reachable_sensitive_resources`` is populated only from an explicit,
trusted ``SensitiveResource`` policy registry.  P1.3 never infers a
classification from a resource name or detector heuristic.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from backend.app.contracts.incident_analysis import BlastRadius, EvidenceItem, SensitiveResource


class ImpactResult(BaseModel):
    """Deterministic impact established for one P1.2 detection finding.

    Every event ID, path, resource, destination, and evidence item must be
    derived from the validated P1.1 graph or the source ``DetectionFinding``.
    ``finding_id`` is the identity of that source finding; P1.4 will assign
    and aggregate incident identities when converting impact results into
    ``IncidentAnalysis``.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    session_id: str

    affected_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    affected_agents: tuple[str, ...] = Field(default_factory=tuple)
    affected_resources: tuple[str, ...] = Field(default_factory=tuple)
    affected_tools: tuple[str, ...] = Field(default_factory=tuple)
    reachable_external_destinations: tuple[str, ...] = Field(default_factory=tuple)
    trust_boundary_event_ids: tuple[str, ...] = Field(default_factory=tuple)

    supporting_graph_paths: tuple[tuple[str, ...], ...] = Field(default_factory=tuple)
    reachable_sensitive_resources: tuple[SensitiveResource, ...] = Field(default_factory=tuple)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    evidence: tuple[EvidenceItem, ...] = Field(default_factory=tuple)

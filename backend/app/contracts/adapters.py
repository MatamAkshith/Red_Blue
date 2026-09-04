"""P1 -> P2 adapter.

Converts deterministic P1 output (AgentEvents + DetectionFindings + AEGIS
ImpactResults) into the frozen `IncidentAnalysis` contract P2 consumes.
Pure field mapping: every value is copied from a P1 fact, nothing is
recomputed, inferred, or invented here.
"""

from __future__ import annotations

from typing import Collection, Sequence

from app.aegis.models import ImpactResult
from app.contracts.incident_analysis import (
    BlastRadius,
    EvidenceItem,
    IncidentAnalysis,
    IncidentSeverity,
    PermissionFact,
)
from app.detection.models import DetectionFinding
from app.events.schemas import AgentEvent

# P1.2 severity vocabulary -> incident severity vocabulary.
_SEVERITY_MAP = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}
_SEVERITY_ORDER = (
    IncidentSeverity.LOW,
    IncidentSeverity.MEDIUM,
    IncidentSeverity.HIGH,
    IncidentSeverity.CRITICAL,
)


def _severity(value) -> IncidentSeverity:
    return _SEVERITY_MAP.get(str(getattr(value, "value", value)).upper(), IncidentSeverity.LOW)


def _ordered_unique(values) -> tuple:
    seen, out = set(), []
    for v in values:
        key = v if isinstance(v, str) else repr(v)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return tuple(out)


def build_incident_analysis(
    incident_id: str,
    events: Sequence[AgentEvent],
    findings: Collection[DetectionFinding],
    impacts: Collection[ImpactResult],
) -> IncidentAnalysis:
    events = list(events)
    findings = list(findings)
    impacts = list(impacts)

    severity = IncidentSeverity.LOW
    for finding in findings:
        candidate = _severity(finding.severity)
        if _SEVERITY_ORDER.index(candidate) > _SEVERITY_ORDER.index(severity):
            severity = candidate

    # Attack path: the longest deterministic graph path P1 reconstructed.
    attack_path: tuple[str, ...] = ()
    for impact in impacts:
        for path in impact.supporting_graph_paths:
            if len(path) > len(attack_path):
                attack_path = tuple(path)
    if not attack_path:
        for finding in findings:
            if len(finding.graph_path) > len(attack_path):
                attack_path = tuple(finding.graph_path)

    incident_type = (
        str(getattr(findings[0].detector_type, "value", findings[0].detector_type))
        if findings
        else "NO_FINDING"
    )

    permissions = _ordered_unique(
        PermissionFact(
            event_id=e.event_id,
            resource=e.resource or "",
            permission=e.permission or "",
            granted=True,
        )
        for e in events
        if e.permission and e.resource
    )

    sensitive_resources = _ordered_unique(
        r for impact in impacts for r in impact.reachable_sensitive_resources
    )
    evidence = [item for impact in impacts for item in impact.evidence]

    # The richest single blast radius AEGIS produced for this incident.
    blast_radius = max(
        (impact.blast_radius for impact in impacts),
        key=lambda b: b.risk_score,
        default=None,
    )

    return IncidentAnalysis(
        incident_id=incident_id,
        agent_id=events[0].agent_id if events else "",
        session_id=events[0].session_id if events else "",
        incident_type=incident_type,
        severity=severity,
        events=events,
        attack_path=attack_path,
        permissions=permissions,
        sensitive_resources=sensitive_resources,
        blast_radius=blast_radius if blast_radius is not None else BlastRadius(),
        evidence=evidence,
    )


"""Evidence -> prompt-ready structure for Featherless.

Consumes app.contracts.incident_analysis.IncidentAnalysis -- the P1 -> P2
contract -- and deterministically compresses it into a compact evidence
package for the LLM prompt. This never asks the LLM to discover security
facts and never infers new ones itself: P1 has already determined the
facts (event types/trust levels, tagged evidence categories, permissions,
sensitive resources, blast radius, attack path); this module only filters,
groups, and summarizes what it's given.
"""

from __future__ import annotations

from typing import Any

from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel

# Recognized EvidenceItem categories the extractor groups by name. Any other
# category value P1 tags is passed through under "anomalies" rather than
# dropped, so new categories never break this module.
_TRUST_BOUNDARY_CROSSING = "trust_boundary_crossing"
_PRIVILEGE_CHANGE = "privilege_change"
_DATA_MOVEMENT = "data_movement"
_EXTERNAL_TRANSMISSION = "external_transmission"
_DETECTION_FINDING = "detection_finding"
_ANOMALY = "anomaly"
_KNOWN_CATEGORIES = (
    _TRUST_BOUNDARY_CROSSING,
    _PRIVILEGE_CHANGE,
    _DATA_MOVEMENT,
    _EXTERNAL_TRANSMISSION,
    _DETECTION_FINDING,
    _ANOMALY,
)


def _dump(event: AgentEvent) -> dict[str, Any]:
    return event.model_dump(mode="json")


# Buckets in a build_prompt_evidence() package that carry an "event_id" key
# per item (used by known_event_ids() below). sensitive_resources_accessed
# is deliberately excluded -- SensitiveResource is about a resource, not a
# specific event, and has no event_id field.
_EVENT_ID_BEARING_BUCKETS = (
    "suspicious_input",
    "trust_boundary_crossings",
    "important_decisions",
    "tool_calls",
    "privilege_changes",
    "data_movement",
    "external_destinations",
    "detection_findings",
    "anomalies",
)


def known_event_ids(evidence: dict[str, Any]) -> set[str]:
    """The full set of event_ids that legitimately appear anywhere in an
    evidence package built by build_prompt_evidence(). Used to check that a
    conclusion referencing an event_id (e.g. Investigation.critical_decision,
    EvidenceInterpretation) is actually grounded in evidence P1 provided --
    not a fabricated ID the LLM invented."""

    ids: set[str] = set(evidence.get("attack_path") or [])

    initial_trigger = evidence.get("initial_trigger")
    if initial_trigger and initial_trigger.get("event_id"):
        ids.add(initial_trigger["event_id"])

    for bucket_name in _EVENT_ID_BEARING_BUCKETS:
        for item in evidence.get(bucket_name) or []:
            event_id = item.get("event_id")
            if event_id:
                ids.add(event_id)

    return ids


def build_prompt_evidence(incident: IncidentAnalysis) -> dict[str, Any]:
    events_by_id = {event.event_id: event for event in incident.events}

    attack_path_events = [
        events_by_id[event_id] for event_id in incident.attack_path if event_id in events_by_id
    ]
    initial_trigger = attack_path_events[0] if attack_path_events else (
        incident.events[0] if incident.events else None
    )

    suspicious_input = [
        event
        for event in incident.events
        if event.trust_level == TrustLevel.UNTRUSTED
        and event.event_type in (EventType.INPUT, EventType.RETRIEVAL)
    ]
    important_decisions = [
        event for event in incident.events if event.event_type == EventType.DECISION
    ]
    tool_calls = [event for event in incident.events if event.event_type == EventType.TOOL_CALL]

    evidence_by_category: dict[str, list[dict[str, Any]]] = {c: [] for c in _KNOWN_CATEGORIES}
    for item in incident.evidence:
        bucket = evidence_by_category.get(item.category, evidence_by_category[_ANOMALY])
        bucket.append(item.model_dump())

    return {
        "incident_id": incident.incident_id,
        "agent_id": incident.agent_id,
        "session_id": incident.session_id,
        "incident_type": incident.incident_type,
        "severity": incident.severity.value,
        "initial_trigger": _dump(initial_trigger) if initial_trigger else None,
        "suspicious_input": [_dump(e) for e in suspicious_input],
        "trust_boundary_crossings": evidence_by_category[_TRUST_BOUNDARY_CROSSING],
        "important_decisions": [_dump(e) for e in important_decisions],
        "tool_calls": [_dump(e) for e in tool_calls],
        "privilege_changes": (
            [p.model_dump() for p in incident.permissions]
            or evidence_by_category[_PRIVILEGE_CHANGE]
        ),
        "sensitive_resources_accessed": [r.model_dump() for r in incident.sensitive_resources],
        "data_movement": evidence_by_category[_DATA_MOVEMENT],
        "external_destinations": evidence_by_category[_EXTERNAL_TRANSMISSION],
        "detection_findings": evidence_by_category[_DETECTION_FINDING],
        "attack_path": list(incident.attack_path),
        "anomalies": evidence_by_category[_ANOMALY],
        "blast_radius": incident.blast_radius.model_dump(),
    }

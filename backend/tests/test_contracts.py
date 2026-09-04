import pytest
from pydantic import ValidationError

from backend.app.aegis.blast_radius import Severity
from backend.app.contracts.incident_analysis import (
    BlastRadius,
    EvidenceItem,
    IncidentAnalysis,
    IncidentSeverity,
    PermissionFact,
    SensitiveResource,
)
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel


def make_incident() -> IncidentAnalysis:
    events = [
        AgentEvent(
            event_id="E14",
            session_id="S1",
            agent_id="A1",
            event_type=EventType.RETRIEVAL,
            source="rag",
            resource="malicious_document",
            trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E15",
            parent_event_id="E14",
            session_id="S1",
            agent_id="A1",
            event_type=EventType.DECISION,
            source="agent",
            trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E16",
            parent_event_id="E15",
            session_id="S1",
            agent_id="A1",
            event_type=EventType.TOOL_CALL,
            source="agent",
            target="crm",
            resource="customer_database",
            permission="privileged",
            trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E17",
            parent_event_id="E16",
            session_id="S1",
            agent_id="A1",
            event_type=EventType.ACTION,
            source="agent",
            target="email",
            trust_level=TrustLevel.UNTRUSTED,
        ),
    ]
    return IncidentAnalysis(
        incident_id="INC-1",
        agent_id="A1",
        session_id="S1",
        incident_type="INDIRECT_PROMPT_INJECTION",
        severity=IncidentSeverity.CRITICAL,
        events=events,
        attack_path=["E14", "E15", "E16", "E17"],
        permissions=[
            PermissionFact(
                event_id="E16", resource="customer_database", permission="read", granted=True
            )
        ],
        sensitive_resources=[
            SensitiveResource(resource="customer_database", severity=Severity.SENSITIVE)
        ],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=["customer_database"],
            reachable_external_destinations=["email"],
            affected_capabilities=["crm_read", "external_send"],
            risk_score=8.5,
        ),
        evidence=[
            EvidenceItem(
                event_id="E15",
                category="trust_boundary_crossing",
                description="Untrusted retrieval influenced agent decision",
            ),
            EvidenceItem(
                event_id="E17",
                category="external_transmission",
                description="Agent attempted to send data externally",
            ),
        ],
    )


def test_valid_incident_parses():
    incident = make_incident()
    assert incident.incident_id == "INC-1"
    assert len(incident.events) == 4
    assert incident.attack_path == ("E14", "E15", "E16", "E17")


def test_missing_required_field_rejected():
    with pytest.raises(ValidationError):
        IncidentAnalysis(agent_id="A1", session_id="S1", incident_type="X")


def test_blast_radius_defaults_when_omitted():
    incident = IncidentAnalysis(
        incident_id="INC-2",
        agent_id="A1",
        session_id="S1",
        incident_type="OTHER",
        severity=IncidentSeverity.LOW,
    )
    assert incident.blast_radius.risk_score == 0.0
    assert incident.events == []

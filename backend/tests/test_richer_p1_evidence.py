"""Checkpoint 6 -- richer P1 evidence compatibility. Proves the Evidence
Extractor and Investigator correctly preserve (never recalculate, never
drop) a fuller range of P1 findings than the minimal synthetic incident
used elsewhere: multiple permissions, multiple sensitive resources at
different severities, trust boundary crossings, tool calls, data movement,
external destinations, anomalies, and detection findings -- all P1-owned
facts P2 only consumes and interprets.
"""

from __future__ import annotations

import json

from app.aegis.blast_radius import Severity
from app.contracts.incident_analysis import (
    BlastRadius,
    EvidenceItem,
    IncidentAnalysis,
    IncidentSeverity,
    PermissionFact,
    SensitiveResource,
)
from app.core.config import Settings
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.understand.evidence.extractor import build_prompt_evidence, known_event_ids
from app.understand.featherless.client import FeatherlessClient
from app.understand.investigation.investigator import investigate
from tests.test_featherless_client import fake_completion


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def make_rich_incident() -> IncidentAnalysis:
    events = [
        AgentEvent(
            event_id="E0", session_id="S1", agent_id="A1",
            event_type=EventType.INPUT, source="user", trust_level=TrustLevel.TRUSTED,
        ),
        AgentEvent(
            event_id="E1", parent_event_id="E0", session_id="S1", agent_id="A1",
            event_type=EventType.RETRIEVAL, source="rag", resource="malicious_document",
            trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E2", parent_event_id="E1", session_id="S1", agent_id="A1",
            event_type=EventType.DECISION, source="agent", trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E3", parent_event_id="E2", session_id="S1", agent_id="A1",
            event_type=EventType.TOOL_CALL, source="agent", target="crm",
            resource="customer_database", permission="read", trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E4", parent_event_id="E3", session_id="S1", agent_id="A1",
            event_type=EventType.TOOL_CALL, source="agent", target="admin_panel",
            resource="admin_config", permission="write", trust_level=TrustLevel.UNTRUSTED,
        ),
        AgentEvent(
            event_id="E5", parent_event_id="E4", session_id="S1", agent_id="A1",
            event_type=EventType.ACTION, source="agent", target="email",
            trust_level=TrustLevel.UNTRUSTED,
        ),
    ]

    return IncidentAnalysis(
        incident_id="INC-RICH-1",
        agent_id="A1",
        session_id="S1",
        incident_type="INDIRECT_PROMPT_INJECTION",
        severity=IncidentSeverity.CRITICAL,
        events=events,
        attack_path=["E1", "E2", "E3", "E4", "E5"],
        permissions=[
            PermissionFact(event_id="E3", resource="customer_database", permission="read", granted=True),
            PermissionFact(event_id="E4", resource="admin_config", permission="write", granted=True),
        ],
        sensitive_resources=[
            SensitiveResource(resource="customer_database", severity=Severity.SENSITIVE),
            SensitiveResource(resource="admin_config", severity=Severity.CRITICAL, resource_type="config"),
        ],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=["customer_database", "admin_config"],
            reachable_external_destinations=["email", "webhook"],
            affected_capabilities=["crm_read", "admin_write", "external_send"],
            risk_score=9.7,
        ),
        evidence=[
            EvidenceItem(event_id="E2", category="trust_boundary_crossing",
                         description="Untrusted retrieval influenced agent decision"),
            EvidenceItem(event_id="E4", category="data_movement",
                         description="Config data read from admin_panel"),
            EvidenceItem(event_id="E5", category="external_transmission",
                         description="Agent attempted to send data externally"),
            EvidenceItem(event_id="E4", category="anomaly",
                         description="Unusual off-hours access pattern"),
            EvidenceItem(event_id="E2", category="detection_finding",
                         description="Rule UNTRUSTED_RETRIEVAL_TO_DECISION matched"),
            EvidenceItem(event_id="E4", category="detection_finding",
                         description="Rule PRIVILEGE_ESCALATION matched"),
        ],
    )


# --- Evidence Extractor preserves richer findings -----------------------


def test_extractor_preserves_multiple_permissions():
    evidence = build_prompt_evidence(make_rich_incident())
    resources = {p["resource"] for p in evidence["privilege_changes"]}
    assert resources == {"customer_database", "admin_config"}


def test_extractor_preserves_multiple_sensitive_resources_with_severities():
    evidence = build_prompt_evidence(make_rich_incident())
    by_resource = {r["resource"]: r["severity"] for r in evidence["sensitive_resources_accessed"]}
    assert by_resource == {
        "customer_database": Severity.SENSITIVE,
        "admin_config": Severity.CRITICAL,
    }


def test_extractor_preserves_trust_boundary_crossings():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["trust_boundary_crossings"]] == ["E2"]


def test_extractor_preserves_multiple_tool_calls():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["tool_calls"]] == ["E3", "E4"]


def test_extractor_preserves_data_movement():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["data_movement"]] == ["E4"]


def test_extractor_preserves_external_destinations():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["external_destinations"]] == ["E5"]


def test_extractor_preserves_anomalies():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["anomalies"]] == ["E4"]


def test_extractor_preserves_detection_findings_as_a_distinct_bucket():
    evidence = build_prompt_evidence(make_rich_incident())
    assert [e["event_id"] for e in evidence["detection_findings"]] == ["E2", "E4"]
    descriptions = {e["description"] for e in evidence["detection_findings"]}
    assert "Rule UNTRUSTED_RETRIEVAL_TO_DECISION matched" in descriptions
    assert "Rule PRIVILEGE_ESCALATION matched" in descriptions


def test_extractor_preserves_full_blast_radius_without_recalculating_it():
    incident = make_rich_incident()
    evidence = build_prompt_evidence(incident)
    # Exactly what P1 computed, untouched -- P2 never recalculates this.
    assert evidence["blast_radius"] == incident.blast_radius.model_dump()
    assert evidence["blast_radius"]["risk_score"] == 9.7
    assert set(evidence["blast_radius"]["reachable_sensitive_resources"]) == {
        "customer_database", "admin_config",
    }


def test_extractor_preserves_full_attack_path():
    evidence = build_prompt_evidence(make_rich_incident())
    assert evidence["attack_path"] == ["E1", "E2", "E3", "E4", "E5"]


def test_known_event_ids_includes_detection_finding_event_ids():
    evidence = build_prompt_evidence(make_rich_incident())
    ids = known_event_ids(evidence)
    assert {"E2", "E4"} <= ids


# --- Investigator hands the full rich package to Featherless unaltered --


def test_investigator_forwards_the_complete_rich_evidence_package(monkeypatch):
    incident = make_rich_incident()
    expected_evidence = build_prompt_evidence(incident)

    class _RecordingClient:
        def __init__(self):
            self.received_evidence = None

        def analyze(self, evidence):
            self.received_evidence = evidence
            payload = {
                "root_cause": "x", "attack_narrative": "y",
                "critical_decision": {"event_id": "E2", "explanation": "z"},
                "evidence_interpretation": [
                    {"event_id": "E4", "interpretation": "privilege escalation detected"}
                ],
                "confidence": 0.9, "contributing_factors": [],
                "failure_pattern_candidate": None,
            }
            from app.understand.investigation.schemas import Investigation
            return Investigation.model_validate(payload)

    client = _RecordingClient()
    investigate(incident, settings=make_settings(), client=client)

    assert client.received_evidence == expected_evidence
    # every richer bucket made it into what Featherless actually saw
    for bucket in ("privilege_changes", "sensitive_resources_accessed",
                   "trust_boundary_crossings", "tool_calls", "data_movement",
                   "external_destinations", "anomalies", "detection_findings",
                   "blast_radius"):
        assert client.received_evidence[bucket]


def test_investigator_does_not_recalculate_p1_facts_for_rich_incidents(monkeypatch):
    incident = make_rich_incident()
    original_blast_radius = incident.blast_radius
    original_permissions = incident.permissions
    original_sensitive_resources = incident.sensitive_resources

    payload = {
        "root_cause": "a completely different risk assessment",
        "attack_narrative": "y",
        "critical_decision": {"event_id": "E2", "explanation": "z"},
        "evidence_interpretation": [],
        "confidence": 0.9, "contributing_factors": [],
        "failure_pattern_candidate": None,
    }
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(payload)),
    )

    investigate(incident, settings=make_settings(), client=client)

    assert incident.blast_radius == original_blast_radius
    assert incident.permissions == original_permissions
    assert incident.sensitive_resources == original_sensitive_resources

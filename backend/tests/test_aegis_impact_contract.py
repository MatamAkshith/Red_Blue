from pydantic import ValidationError
import pytest

from app.aegis.blast_radius import Severity
from app.aegis.models import ImpactResult
from app.contracts.incident_analysis import BlastRadius, EvidenceItem, SensitiveResource


def test_impact_result_has_minimal_empty_impact_defaults():
    result = ImpactResult(finding_id="finding-1", session_id="session-1")

    assert result.affected_event_ids == ()
    assert result.supporting_graph_paths == ()
    assert result.reachable_sensitive_resources == ()
    assert result.blast_radius == BlastRadius()
    assert result.evidence == ()


def test_impact_result_preserves_deterministic_graph_facts():
    resource = SensitiveResource(
        resource="crm://customers",
        severity=Severity.SENSITIVE,
        resource_type="database",
    )
    evidence = EvidenceItem(
        event_id="E2",
        category="external_transmission",
        description="A proven descendant action reached the external destination.",
    )

    result = ImpactResult(
        finding_id="exfil-E1-E3",
        session_id="S1",
        affected_event_ids=["E1", "E2", "E3"],
        affected_agents=["agent-a"],
        affected_resources=["crm://customers"],
        affected_tools=["crm"],
        reachable_external_destinations=["https://external.example/upload"],
        trust_boundary_event_ids=["E1"],
        supporting_graph_paths=[["E1", "E2", "E3"]],
        reachable_sensitive_resources=[resource],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=("crm://customers",),
            reachable_external_destinations=("https://external.example/upload",),
            affected_capabilities=("export",),
            risk_score=7.0,
        ),
        evidence=[evidence],
    )

    assert result.affected_event_ids == ("E1", "E2", "E3")
    assert result.supporting_graph_paths == (("E1", "E2", "E3"),)
    assert result.reachable_sensitive_resources == (resource,)
    assert result.evidence == (evidence,)


def test_impact_result_is_frozen():
    result = ImpactResult(finding_id="finding-1", session_id="session-1")

    with pytest.raises(ValidationError):
        result.finding_id = "other"  # type: ignore[misc]


def test_impact_result_requires_source_finding_and_session_identity():
    with pytest.raises(ValidationError):
        ImpactResult(session_id="session-1")

    with pytest.raises(ValidationError):
        ImpactResult(finding_id="finding-1")

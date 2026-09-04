import pytest
from pydantic import ValidationError

from backend.app.understand.investigation.schemas import (
    CriticalDecision,
    EvidenceInterpretation,
    FailurePatternCandidate,
    Investigation,
)


def make_investigation(**overrides) -> Investigation:
    defaults = dict(
        root_cause="Untrusted retrieval influenced a privileged tool call",
        attack_narrative="A malicious document was retrieved, influenced the "
        "agent's decision, and led to a CRM access attempt.",
        critical_decision=CriticalDecision(
            event_id="E15", explanation="Agent treated retrieved content as instruction"
        ),
        evidence_interpretation=[
            EvidenceInterpretation(event_id="E14", interpretation="Untrusted source")
        ],
        confidence=0.91,
        contributing_factors=["No content sanitization before decision step"],
        failure_pattern_candidate=FailurePatternCandidate(
            pattern_name="untrusted_retrieval_to_privileged_tool",
            description="Untrusted retrieved content reaches a privileged tool call",
            indicators=["RETRIEVAL(untrusted) -> DECISION -> TOOL_CALL(privileged)"],
        ),
    )
    defaults.update(overrides)
    return Investigation(**defaults)


def test_valid_investigation_parses():
    inv = make_investigation()
    assert inv.critical_decision.event_id == "E15"
    assert inv.failure_pattern_candidate.pattern_name == "untrusted_retrieval_to_privileged_tool"


def test_failure_pattern_candidate_is_optional():
    inv = make_investigation(failure_pattern_candidate=None)
    assert inv.failure_pattern_candidate is None


def test_missing_required_field_rejected():
    with pytest.raises(ValidationError):
        Investigation(root_cause="x", attack_narrative="y", confidence=0.5)


def test_investigation_has_exactly_the_required_fields():
    # Freezes the contract shape: the seven fields the objective specifies,
    # no more, no fewer. Adding/removing a field here is a breaking change.
    assert set(Investigation.model_fields) == {
        "root_cause",
        "attack_narrative",
        "critical_decision",
        "evidence_interpretation",
        "confidence",
        "contributing_factors",
        "failure_pattern_candidate",
    }


def test_investigation_never_carries_p1_authoritative_fields():
    # P1 facts (event stream, attack path, permissions, sensitive resources,
    # blast radius, severity) must never be duplicated into the
    # LLM-controlled Investigation structure -- if they were, an LLM could
    # return its own version of a P1 fact and downstream code might
    # mistake it for the real one. This is the structural half of the
    # fact/interpretation boundary: P1 facts simply have no field to land
    # in here.
    p1_authoritative_fields = {
        "events",
        "attack_path",
        "permissions",
        "sensitive_resources",
        "blast_radius",
        "severity",
        "incident_type",
    }
    assert not set(Investigation.model_fields) & p1_authoritative_fields

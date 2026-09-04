import pytest
from pydantic import ValidationError

from app.understand.investigation.schemas import (
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

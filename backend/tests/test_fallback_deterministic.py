from backend.app.understand.evidence.extractor import build_prompt_evidence
from backend.app.understand.fallback.deterministic import fallback_investigation
from tests.test_contracts import make_incident


def test_fallback_confidence_is_zero_and_notice_present():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert result.confidence == 0.0
    assert "AI EXPLANATION:\nUnavailable" in result.root_cause
    assert "AI EXPLANATION:\nUnavailable" in result.attack_narrative


def test_fallback_attack_narrative_uses_confirmed_attack_path():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert "E14 -> E15 -> E16 -> E17" in result.attack_narrative


def test_fallback_critical_decision_is_first_decision_event_labeled_as_inference():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert result.critical_decision.event_id == "E15"
    assert "Deterministic inference" in result.critical_decision.explanation


def test_fallback_contributing_factors_are_labeled_confirmed():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert result.contributing_factors
    assert all(f.startswith("Confirmed:") for f in result.contributing_factors)


def test_fallback_never_fabricates_a_failure_pattern():
    evidence = build_prompt_evidence(make_incident())
    result = fallback_investigation(evidence)

    assert result.failure_pattern_candidate is None


def test_fallback_handles_empty_evidence_without_crashing():
    result = fallback_investigation({})

    assert result.confidence == 0.0
    assert result.critical_decision.event_id == "UNKNOWN"
    assert result.contributing_factors == [
        "Confirmed: no tagged evidence categories present in this package"
    ]

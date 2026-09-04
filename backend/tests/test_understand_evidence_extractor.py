from app.understand.evidence.extractor import build_prompt_evidence
from tests.test_contracts import make_incident


def test_build_prompt_evidence_shapes_the_package():
    incident = make_incident()
    evidence = build_prompt_evidence(incident)

    assert evidence["incident_id"] == "INC-1"
    assert evidence["severity"] == "CRITICAL"
    assert evidence["attack_path"] == ["E14", "E15", "E16", "E17"]

    # initial trigger follows the attack path, not just events[0]
    assert evidence["initial_trigger"]["event_id"] == "E14"

    # untrusted retrieval is surfaced as suspicious input
    assert [e["event_id"] for e in evidence["suspicious_input"]] == ["E14"]

    assert [e["event_id"] for e in evidence["important_decisions"]] == ["E15"]
    assert [e["event_id"] for e in evidence["tool_calls"]] == ["E16"]

    # tagged evidence categories are grouped, not dropped
    assert [e["event_id"] for e in evidence["trust_boundary_crossings"]] == ["E15"]
    assert [e["event_id"] for e in evidence["external_destinations"]] == ["E17"]
    assert evidence["anomalies"] == []

    # P1-determined permission/resource/blast-radius facts pass straight through
    assert evidence["privilege_changes"][0]["resource"] == "customer_database"
    assert evidence["sensitive_resources_accessed"][0]["resource"] == "customer_database"
    assert evidence["blast_radius"]["risk_score"] == 8.5


def test_build_prompt_evidence_handles_no_attack_path():
    incident = make_incident().model_copy(update={"attack_path": []})
    evidence = build_prompt_evidence(incident)
    # falls back to the first event when there's no attack path to anchor on
    assert evidence["initial_trigger"]["event_id"] == "E14"


def test_build_prompt_evidence_unknown_category_falls_back_to_anomalies():
    incident = make_incident()
    incident.evidence[0].category = "something_new"
    evidence = build_prompt_evidence(incident)
    assert evidence["trust_boundary_crossings"] == []
    assert [e["event_id"] for e in evidence["anomalies"]] == ["E15"]

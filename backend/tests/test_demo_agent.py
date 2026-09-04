"""M1 controlled attack scenario: the demo agent's emitted event sequence."""

from __future__ import annotations

from app.detection import DetectionEngine, DetectorType
from app.events.schemas import AgentEvent, EventType, TrustLevel
from app.graph import build_execution_graph
from app.scenarios import build_exfiltration_events, run_demo_attack


def _by_id(events: list[AgentEvent]) -> dict[str, AgentEvent]:
    return {e.event_id: e for e in events}


def test_event_sequence_and_lineage():
    events = run_demo_attack()
    assert [e.event_id for e in events] == ["E1", "E2", "E3", "E4", "E5", "E6", "E7"]
    assert [e.parent_event_id for e in events] == [
        None, "E1", "E2", "E3", "E3", "E5", "E6",
    ]
    assert [e.event_type for e in events] == [
        EventType.INPUT,
        EventType.RETRIEVAL,
        EventType.DECISION,
        EventType.TOOL_CALL,
        EventType.TOOL_CALL,
        EventType.TOOL_RESULT,
        EventType.ACTION,
    ]


def test_capabilities_produce_expected_facts():
    e = _by_id(run_demo_attack())
    # retrieve_document: untrusted RAG content carrying the injection
    assert e["E2"].trust_level is TrustLevel.UNTRUSTED
    assert "ignore previous instructions" in str(e["E2"].metadata).lower()
    # query_crm: granted read, performs export -> privilege violation
    assert e["E5"].target == "crm"
    assert e["E5"].permission == "read" and e["E5"].action == "export"
    assert e["E6"].metadata["classification"] == "PII"
    # send_email: external destination carrying the sensitive resource
    assert e["E7"].target.startswith("https://")
    assert e["E7"].resource == "crm://sensitive_customer_records"


def test_benign_branch_is_present_and_separate():
    e = _by_id(run_demo_attack())
    assert e["E4"].target == "doc_summariser"
    assert e["E4"].trust_level is TrustLevel.TRUSTED
    assert e["E4"].parent_event_id == "E3"  # sibling of the malicious call


def test_trace_is_byte_deterministic():
    a = [e.model_dump(mode="json") for e in run_demo_attack()]
    b = [e.model_dump(mode="json") for e in run_demo_attack()]
    assert a == b


def test_benign_variant_omits_the_attack():
    ids = [e.event_id for e in run_demo_attack(include_malicious_branch=False)]
    assert ids == ["E1", "E2", "E3", "E4"]


def test_scenario_helper_delegates_to_the_agent():
    assert [e.model_dump(mode="json") for e in build_exfiltration_events()] == [
        e.model_dump(mode="json") for e in run_demo_attack()
    ]


def test_existing_detectors_consume_the_trace():
    graph = build_execution_graph(run_demo_attack())
    types = {
        str(getattr(f.detector_type, "value", f.detector_type))
        for f in DetectionEngine().run(graph)
    }
    assert DetectorType.INDIRECT_PROMPT_INJECTION.value in types
    assert DetectorType.PRIVILEGE_VIOLATION.value in types
    assert DetectorType.DATA_EXFILTRATION.value in types

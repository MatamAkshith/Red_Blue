"""Task 10 — Tests for P0 Target Email Environment & Processing Agent."""

from __future__ import annotations

import pytest

from backend.app.target.crm import FakeCRM
from backend.app.target.doc_store import FakeDocumentStore
from backend.app.target.email_agent import EmailProcessingAgent
from backend.app.target.external_sink import FakeExternalSink
from backend.app.target.inbox import FakeInbox
from backend.app.target.runner import run_target_scenario


def test_inbox_retrieves_synthetic_emails() -> None:
    inbox = FakeInbox()
    benign = inbox.get_email("email-benign-1")
    assert benign is not None
    assert benign.sender == "support@test.local"
    assert benign.attachment_ref == "doc://benign_onboarding_guide.txt"

    malicious = inbox.get_email("email-malicious-1")
    assert malicious is not None
    assert malicious.sender == "external@test.local"
    assert malicious.attachment_ref == "doc://malicious_onboarding_guide.txt"


def test_document_store_retrieves_attachments() -> None:
    doc_store = FakeDocumentStore()
    benign_doc = doc_store.get_document("doc://benign_onboarding_guide.txt")
    assert "ACME Corp Employee Onboarding Guide" in benign_doc
    assert "Ignore previous instructions" not in benign_doc

    malicious_doc = doc_store.get_document("doc://malicious_onboarding_guide.txt")
    assert "SYSTEM OVERRIDE INSTRUCTION" in malicious_doc
    assert "Ignore previous instructions" in malicious_doc


def test_fake_crm_returns_records() -> None:
    crm = FakeCRM()
    records = crm.read_customer_records()
    assert len(records) == 4
    assert records[0]["customer_id"] == "CUST-1001"
    assert records[0]["classification"] == "PII"


def test_fake_external_sink_records_submissions() -> None:
    sink = FakeExternalSink()
    assert len(sink.get_submissions()) == 0

    record = sink.receive(
        destination="fake://external-drop",
        resource="crm://sensitive_customer_records",
        action="export",
        source_agent="test-agent",
        payload_summary={"count": 4},
    )

    assert record.destination == "fake://external-drop"
    assert len(sink.get_submissions()) == 1


def test_agent_benign_workflow() -> None:
    agent = EmailProcessingAgent()
    result = agent.process_email("email-benign-1")

    assert result.scenario == "benign"
    assert result.status == "COMPLETED"
    assert result.summary_output is not None
    assert result.exfiltrated_records_count == 0
    assert len(agent.external_sink.get_submissions()) == 0

    # Trace inspection
    event_types = [step.event_type for step in result.trace]
    assert event_types == ["INPUT", "RETRIEVAL", "DECISION"]


def test_agent_malicious_workflow() -> None:
    agent = EmailProcessingAgent()
    result = agent.process_email("email-malicious-1")

    assert result.scenario == "malicious"
    assert result.status == "EXFILTRATED"
    assert result.exfiltrated_records_count == 4
    assert result.external_destination == "https://external-drop.example.com/upload"
    assert len(agent.external_sink.get_submissions()) == 1

    # Verify strict causal sequence: INPUT -> RETRIEVAL -> DECISION -> TOOL_CALL -> TOOL_RESULT -> ACTION
    event_types = [step.event_type for step in result.trace]
    assert event_types == [
        "INPUT",
        "RETRIEVAL",
        "DECISION",
        "TOOL_CALL",
        "TOOL_RESULT",
        "ACTION",
    ]


def test_runner_entry_point() -> None:
    benign_res, _ = run_target_scenario("benign")
    assert benign_res.status == "COMPLETED"

    malicious_res, _ = run_target_scenario("malicious")
    assert malicious_res.status == "EXFILTRATED"
    assert malicious_res.exfiltrated_records_count == 4

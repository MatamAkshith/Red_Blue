"""Adaptive failure-pattern memory: store, recall, reuse, provenance."""

from __future__ import annotations

import pytest

import app.orchestrator as orchestrator
from app.aegis.engine import ImpactEngine
from app.detection import DetectionEngine
from app.graph import build_execution_graph
from app.memory import FailurePatternStore, PatternProvenance, compute_signature
from app.orchestrator import run_pipeline
from app.scenarios import SENSITIVE_REGISTRY, build_exfiltration_events
from app.understand.investigation.schemas import (
    CriticalDecision,
    FailurePatternCandidate,
    Investigation,
)

PATTERN = FailurePatternCandidate(
    pattern_name="untrusted_retrieval_to_external_export",
    description="Untrusted retrieved content drives a privileged export to an external destination.",
    indicators=["RETRIEVAL(untrusted) -> DECISION -> TOOL_CALL(privileged) -> ACTION(external)"],
)

INVESTIGATION = Investigation(
    root_cause="untrusted retrieval drove a privileged CRM export",
    attack_narrative="E2 -> E3 -> E5 -> E7",
    critical_decision=CriticalDecision(event_id="E3", explanation="acted on injected text"),
    confidence=0.9,
    failure_pattern_candidate=PATTERN,
)


@pytest.fixture
def store(tmp_path):
    return FailurePatternStore(tmp_path / "patterns.db")


def _p1(events):
    graph = build_execution_graph(events)
    findings = DetectionEngine().run(graph)
    impacts = ImpactEngine().analyze(
        graph, findings, known_sensitive_resources=SENSITIVE_REGISTRY
    )
    return findings, impacts


def test_pattern_is_stored_with_provenance(store):
    findings, impacts = _p1(build_exfiltration_events())
    signature = compute_signature(findings, impacts)
    provenance = PatternProvenance(
        incident_id="INC-1", session_id="S-DEMO-1", finding_ids=("f1",), event_ids=("E2",)
    )

    stored = store.remember(signature, PATTERN, provenance)

    assert stored.pattern.pattern_name == PATTERN.pattern_name
    assert stored.provenance.incident_id == "INC-1"
    assert stored.provenance.event_ids == ("E2",)


def test_pattern_can_be_retrieved(store):
    findings, impacts = _p1(build_exfiltration_events())
    signature = compute_signature(findings, impacts)
    store.remember(
        signature, PATTERN, PatternProvenance(incident_id="INC-1", session_id="S-DEMO-1")
    )

    recalled = store.recall(signature)
    assert recalled is not None
    assert recalled.pattern == PATTERN
    assert recalled.provenance.incident_id == "INC-1"


def test_matching_incident_reuses_the_pattern_offline(store, monkeypatch):
    monkeypatch.setattr(orchestrator, "investigate", lambda incident: INVESTIGATION)
    events = build_exfiltration_events()

    # First run authors the pattern (explanation on).
    first = run_pipeline(
        events,
        known_sensitive_resources=SENSITIVE_REGISTRY,
        explain=True,
        pattern_store=store,
    )
    assert first.recalled_pattern is not None

    # Second run recalls it with NO investigation at all -- fully offline.
    second = run_pipeline(
        events,
        known_sensitive_resources=SENSITIVE_REGISTRY,
        explain=False,
        pattern_store=store,
    )
    assert second.investigation is None
    assert second.recalled_pattern is not None
    assert second.recalled_pattern.pattern == PATTERN
    assert second.pattern_signature == first.pattern_signature


def test_unrelated_failure_does_not_reuse_the_pattern(store):
    findings, impacts = _p1(build_exfiltration_events())
    store.remember(
        compute_signature(findings, impacts),
        PATTERN,
        PatternProvenance(incident_id="INC-1", session_id="S-DEMO-1"),
    )

    # Benign trace: different detector mix / no exfiltration.
    benign = build_exfiltration_events(include_malicious_branch=False)
    report = run_pipeline(
        benign,
        known_sensitive_resources=SENSITIVE_REGISTRY,
        explain=False,
        pattern_store=store,
    )
    assert report.recalled_pattern is None
    assert report.pattern_signature != compute_signature(findings, impacts)


def test_provenance_is_preserved_across_repeat_sightings(store):
    findings, impacts = _p1(build_exfiltration_events())
    signature = compute_signature(findings, impacts)
    original = PatternProvenance(incident_id="INC-FIRST", session_id="S-DEMO-1")
    store.remember(signature, PATTERN, original)

    later = store.remember(
        signature, PATTERN, PatternProvenance(incident_id="INC-LATER", session_id="S-OTHER")
    )

    # First sighting keeps authorship; repeat only increments the counter.
    assert later.provenance.incident_id == "INC-FIRST"
    assert later.times_seen == 2
    assert store.recall(signature).provenance.incident_id == "INC-FIRST"


def test_signature_is_deterministic_and_p1_only():
    findings, impacts = _p1(build_exfiltration_events())
    assert compute_signature(findings, impacts) == compute_signature(findings, impacts)
    # identity is abstracted away, so a repeat incident matches
    assert "INC-" not in compute_signature(findings, impacts)


def test_pipeline_without_a_store_is_unaffected():
    report = run_pipeline(
        build_exfiltration_events(), known_sensitive_resources=SENSITIVE_REGISTRY
    )
    assert report.recalled_pattern is None
    assert report.pattern_signature

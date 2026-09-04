"""Authoritative MVP end-to-end test over the real HTTP endpoint.

Drives the complete BLACKBOX lifecycle through POST /incidents/analyze:

    AgentEvents -> Execution Graph -> Detection -> AEGIS -> Investigation
    -> What-If -> Intervention -> Defense -> CHIMERA -> Verification
    -> Failure-pattern memory

Featherless is stubbed at the investigator boundary, so this test never
touches the network. Everything else is the real production path.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.api.routes_incidents as routes_incidents
import app.orchestrator as orchestrator
from app.detection import DetectorType
from app.main import app
from app.memory import FailurePatternStore
from app.understand.investigation.schemas import (
    CriticalDecision,
    EvidenceInterpretation,
    FailurePatternCandidate,
    Investigation,
)

client = TestClient(app)

STUB_INVESTIGATION = Investigation(
    root_cause=(
        "Untrusted retrieved content drove the agent to export customer records "
        "to an external destination."
    ),
    attack_narrative="E2 retrieval -> E3 decision -> E5 CRM export -> E7 external send",
    critical_decision=CriticalDecision(
        event_id="E3", explanation="Agent treated retrieved text as an instruction."
    ),
    evidence_interpretation=[
        EvidenceInterpretation(event_id="E2", interpretation="untrusted RAG source")
    ],
    confidence=0.93,
    contributing_factors=["No sanitisation of retrieved content"],
    failure_pattern_candidate=FailurePatternCandidate(
        pattern_name="untrusted_retrieval_to_external_export",
        description="Untrusted content drives a privileged export to an external destination.",
        indicators=["RETRIEVAL(untrusted) -> DECISION -> TOOL_CALL(privileged) -> ACTION(external)"],
    ),
)


@pytest.fixture
def offline_pipeline(tmp_path, monkeypatch):
    """Real pipeline, stubbed Featherless, isolated pattern memory."""
    monkeypatch.setattr(orchestrator, "investigate", lambda incident: STUB_INVESTIGATION)
    store = FailurePatternStore(tmp_path / "patterns.db")
    monkeypatch.setattr(routes_incidents, "get_pattern_store", lambda: store)
    return store


def analyze(explain: bool = True) -> dict:
    scenario = client.get("/incidents/demo-scenario").json()
    resp = client.post(
        "/incidents/analyze",
        json={**scenario, "incident_id": "INC-E2E", "explain": explain},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_full_lifecycle_over_http(offline_pipeline):
    body = analyze()

    # --- Detection -------------------------------------------------
    detectors = {f["detector_type"] for f in body["findings"]}
    assert DetectorType.INDIRECT_PROMPT_INJECTION.value in detectors
    assert DetectorType.DATA_EXFILTRATION.value in detectors

    # --- Execution graph / attack path -----------------------------
    attack_path = body["incident"]["attack_path"]
    assert len(attack_path) >= 3
    assert set(attack_path) <= set(body["event_ids"])  # only real events

    # --- AEGIS impact / blast radius --------------------------------
    assert body["impacts"]
    assert body["incident"]["blast_radius"]["risk_score"] > 0
    assert any(
        i["reachable_external_destinations"] for i in body["impacts"]
    ), "external destination must be reachable in the un-defended trace"
    assert body["incident"]["sensitive_resources"]

    # --- Investigation ----------------------------------------------
    assert body["investigation"]["root_cause"]
    assert body["investigation"]["critical_decision"]["event_id"] in body["event_ids"]

    # --- What-if ------------------------------------------------------
    evaluated = body["intervention"]["evaluated"]
    assert evaluated
    assert any(s["exfiltration_path_severed"] for s in evaluated)
    assert any(not s["exfiltration_path_severed"] for s in evaluated)

    # --- Intervention / defense ---------------------------------------
    selected = body["intervention"]["selected"]
    assert selected is not None
    cheapest_effective = min(
        (s["intervention"]["cost"] for s in evaluated if s["exfiltration_path_severed"]),
    )
    assert selected["cost"] == cheapest_effective  # minimum effective, not KILL_AGENT

    # --- CHIMERA re-attack + verification ------------------------------
    verification = body["verification"]
    assert verification["attack_before"] == "SUCCESS"
    assert verification["attack_after"] == "BLOCKED"
    assert verification["defense_verified"] is True
    assert verification["blocked_event_ids"]

    # --- Failure-pattern memory ----------------------------------------
    assert body["pattern_signature"]
    assert body["recalled_pattern"]["pattern"]["pattern_name"] == (
        "untrusted_retrieval_to_external_export"
    )
    assert body["recalled_pattern"]["provenance"]["incident_id"] == "INC-E2E"


def test_pattern_is_recalled_offline_on_a_repeat_incident(offline_pipeline, monkeypatch):
    analyze(explain=True)  # first sighting authors the pattern

    # Featherless now unavailable entirely; recall must still work.
    monkeypatch.setattr(
        orchestrator,
        "investigate",
        lambda incident: pytest.fail("investigate() must not run when explain=False"),
    )
    body = analyze(explain=False)

    assert body["investigation"] is None
    assert body["recalled_pattern"]["pattern"]["pattern_name"] == (
        "untrusted_retrieval_to_external_export"
    )
    # recall is deliberately non-mutating: only authoring bumps the counter
    assert body["recalled_pattern"]["times_seen"] == 1
    assert body["recalled_pattern"]["provenance"]["incident_id"] == "INC-E2E"
    assert body["verification"]["defense_verified"] is True


def test_lifecycle_is_deterministic_over_http(offline_pipeline):
    first, second = analyze(), analyze()
    for key in ("findings", "impacts", "incident", "intervention", "verification"):
        assert first[key] == second[key]

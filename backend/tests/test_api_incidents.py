"""POST /incidents/analyze -- complete pipeline over HTTP."""

from __future__ import annotations

import backend.app.orchestrator as orchestrator
from fastapi.testclient import TestClient

from backend.app.adapter import build_incident_analysis
from backend.app.detection import DetectionEngine, DetectorType
from backend.app.graph import build_execution_graph
from backend.app.main import app
from backend.app.aegis.engine import ImpactEngine
from backend.app.scenarios import SENSITIVE_REGISTRY, build_exfiltration_events
from backend.app.understand.investigation.schemas import CriticalDecision, Investigation

client = TestClient(app)

FAKE_INVESTIGATION = Investigation(
    root_cause="untrusted retrieval drove a privileged CRM export",
    attack_narrative="E2 -> E3 -> E5 -> E7",
    critical_decision=CriticalDecision(event_id="E3", explanation="acted on injected text"),
    confidence=0.9,
)


def _payload(explain: bool = False) -> dict:
    return {
        "events": [e.model_dump(mode="json") for e in build_exfiltration_events()],
        "known_sensitive_resources": [r.model_dump(mode="json") for r in SENSITIVE_REGISTRY],
        "incident_id": "INC-DEMO",
        "explain": explain,
    }


def test_analyze_returns_the_full_incident_report():
    body = client.post("/incidents/analyze", json=_payload()).json()

    assert len(body["findings"]) == 6                      # detection findings
    assert len(body["impacts"]) == 6                       # AEGIS impact
    assert "incident" in body
    assert body["incident"] is not None
    assert body["incident"]["attack_path"]                 # reconstructed attack path
    assert body["incident"]["blast_radius"]["risk_score"] > 0
    assert body["intervention"]["selected"]["intervention_type"] == "BLOCK_EXTERNAL_DESTINATION"
    assert body["intervention"]["evaluated"]               # what-if simulations
    assert body["verification"]["attack_before"] == "SUCCESS"
    assert body["verification"]["attack_after"] == "BLOCKED"
    assert body["verification"]["defense_verified"] is True


def test_analyze_includes_investigation_when_explain_is_true(monkeypatch):
    monkeypatch.setattr(orchestrator, "investigate", lambda incident: FAKE_INVESTIGATION)
    body = client.post("/incidents/analyze", json=_payload(explain=True)).json()

    assert body["investigation"]["root_cause"].startswith("untrusted retrieval")
    assert body["investigation"]["critical_decision"]["event_id"] == "E3"


def test_analyze_skips_investigation_when_explain_is_false():
    body = client.post("/incidents/analyze", json=_payload(explain=False)).json()
    assert body["investigation"] is None


def test_analyze_rejects_malformed_events():
    resp = client.post("/incidents/analyze", json={"events": [{"event_id": "E1"}]})
    assert resp.status_code == 422


def test_adapter_maps_only_p1_facts():
    events = build_exfiltration_events()
    graph = build_execution_graph(events)
    findings = DetectionEngine().run(graph)
    impacts = ImpactEngine().analyze(
        graph, findings, known_sensitive_resources=SENSITIVE_REGISTRY
    )
    incident = build_incident_analysis(graph, findings, impacts)

    event_ids = {e.event_id for e in events}
    assert set(incident.attack_path) <= event_ids
    assert {p.event_id for p in incident.permissions} <= event_ids
    assert {e.event_id for e in incident.evidence} <= event_ids
    assert incident.session_id == events[0].session_id


def test_analyze_is_deterministic():
    a = client.post("/incidents/analyze", json=_payload()).json()
    b = client.post("/incidents/analyze", json=_payload()).json()
    assert a == b

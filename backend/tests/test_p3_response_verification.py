"""P3 Integration Tests — Response Pipeline, What-If, Intervention, CHIMERA, Verification, & Master Demo Runner."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from backend.app.events.collector import EventCollector
from backend.app.events.schemas import AgentEvent
from backend.app.events.storage import EventStore
from backend.app.graph import build_execution_graph
from backend.app.intervention.engine import select_minimum_effective
from backend.app.orchestrator import run_pipeline
from backend.app.target.demo_runner import reset_demo_database, run_full_p3_demo
from backend.app.target.runner import run_target_scenario
from backend.app.whatif.simulator import simulate


@pytest.fixture
def tmp_store():
    tmp_db = Path(tempfile.gettempdir()) / "p3_test_store.db"
    if tmp_db.exists():
        tmp_db.unlink()
    store = EventStore(tmp_db)
    yield store
    if tmp_db.exists():
        tmp_db.unlink()


def test_p3_whatif_integration(tmp_store):
    """Verify existing What-If simulator runs counterfactual simulation over live target events."""
    collector = EventCollector(tmp_store)
    result, events = run_target_scenario(
        scenario="malicious",
        live=True,
        collector=collector,
        session_id="S-P3-TEST-WHATIF",
    )
    assert len(events) == 6

    report = run_pipeline(events, include_investigation=False)
    assert report.intervention.selected is not None

    intervention = report.intervention.selected
    graph = build_execution_graph(events)

    sim_res = simulate(events, graph, intervention)
    assert sim_res.exfiltration_path_severed is True
    assert "E6" in sim_res.removed_event_ids


def test_p3_intervention_selection(tmp_store):
    """Verify existing InterventionEngine derives candidate from live incident facts."""
    collector = EventCollector(tmp_store)
    result, events = run_target_scenario(
        scenario="malicious",
        live=True,
        collector=collector,
        session_id="S-P3-TEST-INTERVENTION",
    )

    report = run_pipeline(events, include_investigation=False)
    decision = report.intervention
    assert decision.selected is not None
    assert decision.selected.intervention_type.value == "BLOCK_EXTERNAL_DESTINATION"
    assert "https://external-drop.example.com/upload" in decision.selected.value
    assert decision.selected.cost == 1


def test_p3_chimera_reattack_and_verification(tmp_store):
    """Verify existing CHIMERA replay performs controlled re-attack and verifies defense."""
    collector = EventCollector(tmp_store)
    result, events = run_target_scenario(
        scenario="malicious",
        live=True,
        collector=collector,
        session_id="S-P3-TEST-VERIFY",
    )

    report = run_pipeline(events, include_investigation=False)
    verif = report.verification
    assert verif.attack_before == "SUCCESS"
    assert verif.attack_after == "BLOCKED"
    assert verif.defense_verified is True
    assert "E6" in verif.blocked_event_ids


def test_p3_historical_events_immutability(tmp_store):
    """Verify historical AgentEvent telemetry is never mutated by defense/verification."""
    collector = EventCollector(tmp_store)
    _, events = run_target_scenario(
        scenario="malicious",
        live=True,
        collector=collector,
        session_id="S-P3-TEST-IMMUTABLE",
    )
    original_event_count = len(events)
    original_event_ids = [e.event_id for e in events]

    # Run response pipeline
    run_pipeline(events, include_investigation=False)

    # Verify original events list and objects remain completely unchanged
    assert len(events) == original_event_count
    assert [e.event_id for e in events] == original_event_ids


def test_p3_demo_runner_benign_and_malicious(capsys, tmp_store):
    """Verify master demo runner executes benign and malicious scenarios cleanly."""
    run_full_p3_demo(scenario="benign", session_id="S-P3-BENIGN-TEST")
    captured = capsys.readouterr()
    assert "Deterministic Findings: 0" in captured.out

    run_full_p3_demo(scenario="malicious", session_id="S-P3-MALICIOUS-TEST")
    captured_mal = capsys.readouterr()
    assert "Defense Verified      : TRUE" in captured_mal.out

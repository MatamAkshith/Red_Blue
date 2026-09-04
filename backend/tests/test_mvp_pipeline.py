"""MVP vertical slice: injection -> exfiltration -> defense -> verification."""

from __future__ import annotations

import pytest

from app.detection import DetectorType
from app.graph import build_execution_graph
from app.intervention.engine import build_candidates, select_minimum_effective
from app.intervention.models import (
    InterventionType,
    apply_intervention,
    build_intervention,
)
from app.orchestrator import run_pipeline
from app.scenarios import SENSITIVE_REGISTRY, build_exfiltration_events
from app.whatif.simulator import simulate


def _detector_types(findings) -> set[str]:
    return {str(getattr(f.detector_type, "value", f.detector_type)) for f in findings}


@pytest.fixture
def report():
    return run_pipeline(
        build_exfiltration_events(), known_sensitive_resources=SENSITIVE_REGISTRY
    )


def test_scenario_triggers_all_three_detectors(report):
    assert _detector_types(report.findings) == {
        DetectorType.INDIRECT_PROMPT_INJECTION.value,
        DetectorType.PRIVILEGE_VIOLATION.value,
        DetectorType.DATA_EXFILTRATION.value,
    }


def test_impact_reaches_sensitive_data_and_external_destination(report):
    resources = {
        r.resource for i in report.impacts for r in i.reachable_sensitive_resources
    }
    destinations = {d for i in report.impacts for d in i.reachable_external_destinations}
    assert "crm://sensitive_customer_records" in resources
    assert "https://external-drop.example.com/upload" in destinations


def test_every_impact_event_exists_in_the_graph(report):
    graph = build_execution_graph(build_exfiltration_events())
    for impact in report.impacts:
        for event_id in impact.affected_event_ids:
            assert graph.has_node(event_id)


def test_minimum_effective_intervention_is_selected_not_kill_agent(report):
    selected = report.intervention.selected
    assert selected is not None
    assert selected.intervention_type is InterventionType.BLOCK_EXTERNAL_DESTINATION
    assert selected.cost == 1


def test_defense_is_verified_by_reattack(report):
    assert report.verification.attack_before == "SUCCESS"
    assert report.verification.attack_after == "BLOCKED"
    assert report.verification.defense_verified is True


def test_intervention_removes_event_and_its_descendants():
    events = build_exfiltration_events()
    graph = build_execution_graph(events)
    surviving = apply_intervention(
        events, graph, build_intervention(InterventionType.BLOCK_TOOL, "crm")
    )
    ids = {e.event_id for e in surviving}
    assert "E5" not in ids and "E6" not in ids and "E7" not in ids
    assert "E4" in ids  # benign sibling branch untouched


def test_whatif_is_deterministic_and_repeatable():
    events = build_exfiltration_events()
    graph = build_execution_graph(events)
    candidate = build_intervention(
        InterventionType.BLOCK_EXTERNAL_DESTINATION,
        "https://external-drop.example.com/upload",
    )
    runs = [
        simulate(events, graph, candidate, known_sensitive_resources=SENSITIVE_REGISTRY)
        for _ in range(3)
    ]
    assert all(r == runs[0] for r in runs)
    assert runs[0].exfiltration_path_severed is True


def test_candidates_are_derived_only_from_impact_facts(report):
    candidates = build_candidates(report.impacts)
    values = {c.value for c in candidates}
    known = set()
    for impact in report.impacts:
        known.update(impact.reachable_external_destinations)
        known.update(r.resource for r in impact.reachable_sensitive_resources)
        known.update(impact.affected_tools)
        known.update(impact.affected_agents)
    assert values <= known


def test_benign_trace_yields_no_exfiltration_and_no_intervention():
    events = build_exfiltration_events(include_malicious_branch=False)
    report = run_pipeline(events, known_sensitive_resources=SENSITIVE_REGISTRY)
    assert DetectorType.DATA_EXFILTRATION.value not in _detector_types(report.findings)
    assert report.intervention.selected is None


def test_pipeline_is_deterministic():
    runs = [
        run_pipeline(
            build_exfiltration_events(), known_sensitive_resources=SENSITIVE_REGISTRY
        )
        for _ in range(3)
    ]
    assert all(r == runs[0] for r in runs)

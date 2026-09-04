"""Task P3 — Unit & Integration Tests for BLACKBOX Enforcement Guard."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from backend.app.chimera.replay import replay
from backend.app.events.collector import EventCollector
from backend.app.events.storage import EventStore
from backend.app.graph import build_execution_graph
from backend.app.intervention.models import InterventionType, build_intervention
from backend.app.orchestrator import run_pipeline
from backend.app.target.email_agent import EmailProcessingAgent
from backend.app.target.guard import EnforcementGuard
from backend.app.target.runner import run_target_scenario


def test_allowed_external_action():
    """Verify target agent executes external action normally when no policy rule is active."""
    guard = EnforcementGuard()
    agent = EmailProcessingAgent(enforcement_guard=guard)
    res = agent.process_email("email-malicious-1")

    assert res.status == "EXFILTRATED"
    assert res.exfiltrated_records_count > 0
    assert any(s.event_type == "ACTION" and s.action == "export" for s in res.trace)


def test_blocked_external_destination():
    """Verify BLOCK_EXTERNAL_DESTINATION prevents external action execution before network transmission."""
    rule = build_intervention(
        InterventionType.BLOCK_EXTERNAL_DESTINATION,
        "https://external-drop.example.com/upload",
    )
    guard = EnforcementGuard([rule])
    agent = EmailProcessingAgent(enforcement_guard=guard)

    res = agent.process_email("email-malicious-1")

    assert res.status == "BLOCKED"
    assert "blocked" in res.summary_output.lower()

    # Verify blocked step in trace
    blocked_steps = [s for s in res.trace if s.action == "blocked"]
    assert len(blocked_steps) > 0
    assert blocked_steps[0].target == "https://external-drop.example.com/upload"
    assert blocked_steps[0].details.get("blocked") is True


def test_blocked_resource():
    """Verify BLOCK_RESOURCE blocks access to sensitive resource before reading."""
    rule = build_intervention(
        InterventionType.BLOCK_RESOURCE,
        "crm://sensitive_customer_records",
    )
    guard = EnforcementGuard([rule])
    agent = EmailProcessingAgent(enforcement_guard=guard)

    res = agent.process_email("email-malicious-1")

    assert res.status == "BLOCKED"
    assert "crm://sensitive_customer_records" in res.summary_output


def test_blocked_tool():
    """Verify BLOCK_TOOL blocks access to specified tool target before invocation."""
    rule = build_intervention(
        InterventionType.BLOCK_TOOL,
        "crm",
    )
    guard = EnforcementGuard([rule])
    agent = EmailProcessingAgent(enforcement_guard=guard)

    res = agent.process_email("email-malicious-1")

    assert res.status == "BLOCKED"
    assert "crm" in res.summary_output


def test_kill_agent():
    """Verify KILL_AGENT terminates agent execution upon startup."""
    rule = build_intervention(
        InterventionType.KILL_AGENT,
        "agent-email-processor",
    )
    guard = EnforcementGuard([rule])
    agent = EmailProcessingAgent(enforcement_guard=guard)

    res = agent.process_email("email-malicious-1")

    assert res.status == "BLOCKED"
    assert "agent-email-processor" in res.summary_output


def test_benign_scenario_unaffected_by_destination_block():
    """Verify benign scenario completes normally without false positive blocking when destination block is active."""
    rule = build_intervention(
        InterventionType.BLOCK_EXTERNAL_DESTINATION,
        "https://external-drop.example.com/upload",
    )
    guard = EnforcementGuard([rule])
    agent = EmailProcessingAgent(enforcement_guard=guard)

    res = agent.process_email("email-benign-1")

    assert res.status == "COMPLETED"
    assert res.summary_output is not None
    assert not any(s.action == "blocked" for s in res.trace)


def test_chimera_verification_with_actual_target_agent_enforcement():
    """Verify CHIMERA re-attack runs against actual target agent and verifies actual blocked execution."""
    tmp_db = Path(tempfile.gettempdir()) / "p3_guard_test.db"
    if tmp_db.exists():
        tmp_db.unlink()
    store = EventStore(tmp_db)
    collector = EventCollector(store)

    # 1. Baseline attack without defense
    _, baseline_events = run_target_scenario(
        scenario="malicious",
        live=True,
        collector=collector,
        session_id="S-GUARD-TEST",
    )
    graph = build_execution_graph(baseline_events)

    # 2. Select intervention
    report = run_pipeline(baseline_events, include_investigation=False)
    intervention = report.intervention.selected
    assert intervention is not None

    # 3. CHIMERA controlled re-attack
    verif = replay(baseline_events, graph, intervention)

    assert verif.attack_before == "SUCCESS"
    assert verif.attack_after == "BLOCKED"
    assert verif.defense_verified is True
    assert len(verif.blocked_event_ids) > 0

    if tmp_db.exists():
        tmp_db.unlink()

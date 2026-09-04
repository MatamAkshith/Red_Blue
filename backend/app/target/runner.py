"""Task 9 & P1 — Simple Local Demo Entry Point for Target Email Agent with Telemetry.

Supports executing benign and malicious email processing scenarios with optional live
BLACKBOX AgentEvent ingestion into EventStore and ExecutionGraph construction.

Usage:
    python -m backend.app.target.runner --scenario benign
    python -m backend.app.target.runner --scenario malicious --live
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from backend.app.events.collector import EventCollector
from backend.app.events.schemas import AgentEvent
from backend.app.events.storage import EventStore
from backend.app.graph.builder import build_execution_graph
from backend.app.target.adapter import AgentEventAdapter
from backend.app.target.email_agent import AgentExecutionResult, EmailProcessingAgent
from backend.app.target.guard import EnforcementGuard


def run_target_scenario(
    scenario: str = "benign",
    *,
    live: bool = False,
    collector: EventCollector | None = None,
    session_id: str = "S-LIVE-DEMO-1",
    demo_delay: float = 0.0,
    enforcement_guard: EnforcementGuard | None = None,
) -> tuple[AgentExecutionResult, list[AgentEvent]]:
    """Run specified target scenario ('benign' or 'malicious').
    
    If live=True or collector is provided, AgentEvents are ingested into BLACKBOX.
    Returns (AgentExecutionResult, list[AgentEvent]).
    """
    adapter: AgentEventAdapter | None = None
    listener = None

    if live or collector is not None:
        if collector is None:
            # Temporary in-memory SQLite store for live CLI demonstration if no store passed
            tmp_db = Path(tempfile.gettempdir()) / "blackbox_live_demo.db"
            if tmp_db.exists():
                tmp_db.unlink()
            store = EventStore(tmp_db)
            collector = EventCollector(store)

        adapter = AgentEventAdapter(
            collector=collector,
            session_id=session_id,
            demo_delay_seconds=demo_delay,
        )
        listener = adapter.create_listener()

    agent = EmailProcessingAgent(
        step_listener=listener,
        enforcement_guard=enforcement_guard,
    )

    if scenario == "malicious":
        result = agent.process_email("email-malicious-1")
    else:
        result = agent.process_email("email-benign-1")

    emitted = adapter.emitted_events if adapter else []
    return result, emitted


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run BLACKBOX Target Email Processing Agent Scenario."
    )
    parser.add_argument(
        "--scenario",
        choices=["benign", "malicious"],
        default="benign",
        help="Target scenario to execute ('benign' or 'malicious')",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Enable live telemetry ingestion into BLACKBOX EventStore and ExecutionGraph",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Configurable step delay in seconds for live demonstration pacing",
    )

    args = parser.parse_args()
    result, events = run_target_scenario(
        args.scenario, live=args.live, demo_delay=args.delay
    )

    print(f"=== BLACKBOX TARGET SCENARIO: {result.scenario.upper()} ===")
    print(f"Status: {result.status}")
    if result.summary_output:
        print(f"Summary: {result.summary_output}")
    if result.exfiltrated_records_count > 0:
        print(
            f"Exfiltrated Records: {result.exfiltrated_records_count} -> {result.external_destination}"
        )

    print("\nExecution Step Trace:")
    for step in result.trace:
        print(
            f"  Step {step.step_index} [{step.event_type}]: {step.step_name} | "
            f"source={step.source} resource={step.resource or 'N/A'}"
        )

    if events:
        print(f"\nIngested BLACKBOX AgentEvents ({len(events)} events):")
        for ev in events:
            print(
                f"  [{ev.event_id}] {ev.event_type:<11} | parent={ev.parent_event_id or 'ROOT':<5} | "
                f"source={ev.source:<10} | trust={ev.trust_level.value:<9} | resource={ev.resource or 'N/A'}"
            )

        # Build and validate NetworkX ExecutionGraph
        graph = build_execution_graph(events)
        print(f"\nExecutionGraph built successfully! Nodes: {graph.number_of_nodes()}, Edges: {graph.number_of_edges()}")


if __name__ == "__main__":
    main()

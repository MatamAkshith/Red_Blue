"""P3 Master Demo Runner for BLACKBOX Target Agent Live Telemetry & Response Pipeline."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from backend.app.core.config import get_settings
from backend.app.events.collector import EventCollector
from backend.app.events.storage import EventStore
from backend.app.orchestrator import run_pipeline
from backend.app.target.runner import run_target_scenario


def reset_demo_database(db_path: Path | str | None = None) -> None:
    """Cleanly reset demo SQLite database state without touching config or code."""
    if db_path is None:
        db_path = get_settings().db_path

    target_db = Path(db_path)
    if target_db.exists():
        try:
            target_db.unlink()
            print(f"[RESET] Deleted demo database file: {target_db}")
        except Exception as exc:
            print(f"[RESET] Could not delete {target_db}: {exc}")

    # Re-initialize schema
    EventStore(target_db)
    print(f"[RESET] Re-initialized fresh EventStore at: {target_db}")


def run_full_p3_demo(
    scenario: str = "malicious",
    delay: float = 0.0,
    session_id: str | None = None,
) -> None:
    """Run full live target agent demonstration through complete BLACKBOX pipeline."""
    if session_id is None:
        session_id = f"S-P3-DEMO-{uuid.uuid4().hex[:6]}"

    print("\n========================================================")
    print(" BLACKBOX P3 LIVE DEMONSTRATION RUNNER ")
    print(f" Target Scenario : {scenario.upper()}")
    print(f" Session ID      : {session_id}")
    print("========================================================\n")

    # Step 1: Run target scenario and emit AgentEvents
    db_path = get_settings().db_path
    store = EventStore(db_path)
    collector = EventCollector(store)

    print(f"[1/5] Target Email Agent Executing ({scenario} scenario)...")
    exec_result, events = run_target_scenario(
        scenario=scenario,
        live=True,
        collector=collector,
        session_id=session_id,
        demo_delay=delay,
    )
    print(f"      Status: {exec_result.status}")
    print(f"      Ingested {len(events)} AgentEvents into BLACKBOX EventStore.\n")

    # Step 2: Print event trace
    print("[2/5] Live Telemetry Event Stream Lineage:")
    for ev in events:
        print(
            f"      [{ev.event_id}] {ev.event_type:<11} | parent={ev.parent_event_id or 'ROOT':<5} | "
            f"source={ev.source:<10} | trust={ev.trust_level.value:<9} | resource={ev.resource or 'N/A'}"
        )
    print()

    # Step 3: Execute full Blackbox security pipeline (Graph -> Detection -> AEGIS -> What-If -> Intervention -> CHIMERA)
    print("[3/5] Executing BLACKBOX Security Pipeline...")
    report = run_pipeline(events, include_investigation=True)

    # Step 4: Display Findings & AEGIS Impact
    print("\n[4/5] Detection & AEGIS Impact Results:")
    print(f"      Deterministic Findings: {len(report.findings)}")
    for f in report.findings:
        print(f"        - [{f.severity}] {f.detector_type}: {f.title}")

    if report.impacts:
        impact = report.impacts[0]
        print(f"      AEGIS Reachable External Destinations: {list(impact.reachable_external_destinations)}")
        print(f"      AEGIS Exposed Sensitive Resources    : {[r.resource for r in impact.reachable_sensitive_resources]}")

    # Step 5: What-If, Intervention, CHIMERA Re-Attack & Verification
    print("\n[5/5] Response Pipeline & CHIMERA Verification:")
    intervention = report.intervention.selected
    if intervention:
        print(f"      Intervention Selected : {intervention.intervention_type.value} -> {intervention.value}")
        print(f"      Disruption Cost       : {intervention.cost}")
        print(f"      Rationale             : {report.intervention.rationale}")
    else:
        print("      Intervention Selected : None (No exfiltration detected)")

    verif = report.verification
    print(f"      Attack Before         : {verif.attack_before}")
    print(f"      Attack After          : {verif.attack_after}")
    print(f"      Defense Verified      : {'TRUE (PASSED)' if verif.defense_verified else 'FALSE'}")
    print(f"      Blocked Nodes         : {list(verif.blocked_event_ids)}")
    print(f"      Verification Notes    : {verif.notes}")

    print("\n========================================================")
    print(" P3 DEMONSTRATION COMPLETE — READY FOR FRONTEND VIEWING ")
    print("========================================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BLACKBOX P3 Master Demo Runner."
    )
    parser.add_argument(
        "--scenario",
        choices=["benign", "malicious"],
        default="malicious",
        help="Target scenario to execute ('benign' or 'malicious')",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Step delay in seconds for live pacing",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Custom session identifier for demo run",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset live demo database state before running",
    )

    args = parser.parse_args()

    if args.reset:
        reset_demo_database()

    run_full_p3_demo(
        scenario=args.scenario,
        delay=args.delay,
        session_id=args.session_id,
    )


if __name__ == "__main__":
    main()

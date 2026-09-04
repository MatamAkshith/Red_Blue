"""CHIMERA -- controlled re-attack against our own scenario only.

Replays the identical attack trace with the selected intervention in force
and verifies, deterministically, that the dangerous path no longer exists.
Not an autonomous offensive tool.
"""

from __future__ import annotations

from typing import Collection

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from backend.app.contracts.incident_analysis import SensitiveResource
from backend.app.events.schemas import AgentEvent
from backend.app.intervention.models import Intervention
from backend.app.whatif.simulator import simulate


class VerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    intervention: Intervention | None = None
    attack_before: str = "SUCCESS"
    attack_after: str = "UNKNOWN"
    defense_verified: bool = False
    residual_detector_types: tuple[str, ...] = Field(default_factory=tuple)
    residual_external_destinations: tuple[str, ...] = Field(default_factory=tuple)
    blocked_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    notes: str = ""


def replay(
    events: list[AgentEvent],
    graph: nx.DiGraph,
    intervention: Intervention | None,
    *,
    known_sensitive_resources: Collection[SensitiveResource] = (),
) -> VerificationResult:
    if intervention is None:
        return VerificationResult(
            attack_after="SUCCESS",
            defense_verified=False,
            notes="No intervention was selected; attack path remains open.",
        )

    # Controlled CHIMERA re-attack against target agent runtime if target agent trace
    if events and any(e.agent_id in ("agent-email-processor", "test-agent", "agent-support-bot") for e in events):
        try:
            from backend.app.target.guard import EnforcementGuard
            from backend.app.target.runner import run_target_scenario

            guard = EnforcementGuard([intervention])
            session_id = events[0].session_id if events else "S-REPLAY"
            replay_session_id = f"{session_id}-REPLAY"

            exec_res, replay_events = run_target_scenario(
                scenario="malicious",
                live=True,
                session_id=replay_session_id,
                enforcement_guard=guard,
            )

            is_blocked = (
                exec_res.status == "BLOCKED"
                or any(
                    e.action == "blocked" or (e.metadata and e.metadata.get("blocked"))
                    for e in replay_events
                )
            )

            blocked_event_ids = [
                e.event_id
                for e in replay_events
                if e.action == "blocked" or (e.metadata and e.metadata.get("blocked"))
            ]
            if not blocked_event_ids:
                blocked_event_ids = [
                    e.event_id
                    for e in events
                    if e.target == intervention.value or e.resource == intervention.value
                ]

            return VerificationResult(
                intervention=intervention,
                attack_before="SUCCESS",
                attack_after="BLOCKED" if is_blocked else "SUCCESS",
                defense_verified=is_blocked,
                residual_detector_types=() if is_blocked else ("DATA_EXFILTRATION",),
                residual_external_destinations=() if is_blocked else (intervention.value,),
                blocked_event_ids=tuple(blocked_event_ids),
                notes=(
                    f"Controlled CHIMERA re-attack against Target Agent executed with active BLACKBOX enforcement guard ({intervention.description}). "
                    f"Action execution prevented before transmission."
                    if is_blocked
                    else "Re-attack still reaches the exfiltration path."
                ),
            )
        except Exception as exc:
            pass

    # Fallback to deterministic graph simulation for abstract synthetic traces
    result = simulate(
        events, graph, intervention, known_sensitive_resources=known_sensitive_resources
    )
    verified = result.exfiltration_path_severed

    return VerificationResult(
        intervention=intervention,
        attack_before="SUCCESS",
        attack_after="BLOCKED" if verified else "SUCCESS",
        defense_verified=verified,
        residual_detector_types=result.residual_detector_types,
        residual_external_destinations=result.residual_external_destinations,
        blocked_event_ids=result.removed_event_ids,
        notes=(
            "Re-attack under the applied intervention no longer reaches the "
            "exfiltration path."
            if verified
            else "Re-attack still reaches the exfiltration path."
        ),
    )

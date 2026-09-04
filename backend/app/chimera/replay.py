"""CHIMERA -- controlled re-attack against our own scenario only.

Replays the identical attack trace with the selected intervention in force
and verifies, deterministically, that the dangerous path no longer exists.
Not an autonomous offensive tool.
"""

from __future__ import annotations

from typing import Collection

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from app.contracts.incident_analysis import SensitiveResource
from app.events.schemas import AgentEvent
from app.intervention.models import Intervention
from app.whatif.simulator import simulate


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

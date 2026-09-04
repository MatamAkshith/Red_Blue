from __future__ import annotations

from collections.abc import Collection
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.aegis.models import ImpactResult
from backend.app.contracts.incident_analysis import IncidentAnalysis
from backend.app.detection.models import DetectionFinding
from backend.app.memory.patterns import FailurePatternStore, compute_signature


class ProtectionSignal(BaseModel):
    """Advisory protection signal produced when an incoming incident matches
    a historical failure pattern stored in memory.

    CRITICAL INVARIANT: This signal is strictly advisory and NEVER overrides
    P1/P2 findings, AEGIS impact, or IncidentAnalysis.
    """

    model_config = ConfigDict(frozen=True)

    matched: bool = True
    pattern_signature: str
    prior_incident_id: str
    prior_session_id: str
    recommendation: str = (
        "PRIOR PATTERN DETECTED. Increase scrutiny / require deterministic security evaluation."
    )


def check_future_protection(
    incident_analysis: IncidentAnalysis | None = None,
    pattern_store: FailurePatternStore | None = None,
    findings: Collection[DetectionFinding] | None = None,
    impacts: Collection[ImpactResult] | None = None,
) -> ProtectionSignal | None:
    """Checks whether an incoming incident matches a stored historical failure pattern.

    Args:
        incident_analysis: Incoming IncidentAnalysis contract.
        pattern_store: Persistent FailurePatternStore instance.
        findings: Optional explicit findings collection.
        impacts: Optional explicit AEGIS impacts collection.

    Returns:
        Populated ProtectionSignal if a historical pattern match is found, or None.
    """
    if pattern_store is None:
        return None

    if findings is not None and impacts is not None:
        signature = compute_signature(findings, impacts)
    elif incident_analysis is not None:
        detectors = sorted(
            {
                d.strip()
                for d in incident_analysis.incident_type.split(",")
                if d.strip()
            }
        )
        resources = sorted(
            {r.resource for r in incident_analysis.sensitive_resources}
            | set(incident_analysis.blast_radius.reachable_sensitive_resources)
        )
        reached_external = bool(
            incident_analysis.blast_radius.reachable_external_destinations
        )
        signature = "|".join(
            [",".join(detectors), ",".join(resources), f"external={reached_external}"]
        )
    else:
        return None

    if not signature:
        return None

    stored = pattern_store.recall(signature)
    if stored is None:
        return None

    return ProtectionSignal(
        matched=True,
        pattern_signature=stored.signature,
        prior_incident_id=stored.provenance.incident_id,
        prior_session_id=stored.provenance.session_id,
        recommendation=(
            "PRIOR PATTERN DETECTED. Increase scrutiny / require deterministic security evaluation."
        ),
    )

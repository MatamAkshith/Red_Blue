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
    incident_analysis: Any = None,
    pattern_store: Any = None,
    findings: Collection[DetectionFinding] | None = None,
    impacts: Collection[ImpactResult] | None = None,
) -> ProtectionSignal | None:
    """Checks whether an incoming incident matches a stored historical failure pattern.

    Args:
        incident_analysis: Incoming IncidentAnalysis contract or duck-typed incident object.
        pattern_store: Persistent FailurePatternStore instance or mock pattern store.
        findings: Optional explicit findings collection.
        impacts: Optional explicit AEGIS impacts collection.

    Returns:
        Populated ProtectionSignal if a historical pattern match is found, or None.
    """
    if pattern_store is None:
        return None

    signature = ""
    if findings is not None and impacts is not None:
        signature = compute_signature(findings, impacts)
    elif incident_analysis is not None:
        raw_type = getattr(incident_analysis, "incident_type", "") or ""
        detectors = sorted({d.strip() for d in str(raw_type).split(",") if d.strip()})

        sensitive_res = getattr(incident_analysis, "sensitive_resources", []) or []
        blast_radius = getattr(incident_analysis, "blast_radius", None)

        reachable_sens: list[Any] = []
        reachable_ext: list[Any] = []
        if blast_radius is not None:
            if isinstance(blast_radius, dict):
                reachable_sens = blast_radius.get("reachable_sensitive_resources", []) or []
                reachable_ext = blast_radius.get("reachable_external_destinations", []) or []
            else:
                reachable_sens = (
                    getattr(blast_radius, "reachable_sensitive_resources", []) or []
                )
                reachable_ext = (
                    getattr(blast_radius, "reachable_external_destinations", []) or []
                )

        resources = sorted(
            {getattr(r, "resource", str(r)) for r in sensitive_res}
            | {getattr(r, "resource", str(r)) for r in reachable_sens}
        )
        reached_external = bool(reachable_ext)
        signature = "|".join(
            [",".join(detectors), ",".join(resources), f"external={reached_external}"]
        )

    if not signature:
        return None

    stored: Any = None
    if hasattr(pattern_store, "recall"):
        stored = pattern_store.recall(signature)
    if stored is None and hasattr(pattern_store, "get_by_signature"):
        stored = pattern_store.get_by_signature(signature)

    if stored is None:
        return None

    prov = getattr(stored, "provenance", stored)
    prior_inc_id = getattr(prov, "incident_id", getattr(stored, "incident_id", "UNKNOWN"))
    prior_sess_id = getattr(prov, "session_id", getattr(stored, "session_id", "UNKNOWN"))
    sig_str = getattr(stored, "signature", signature)

    return ProtectionSignal(
        matched=True,
        pattern_signature=sig_str,
        prior_incident_id=prior_inc_id,
        prior_session_id=prior_sess_id,
        recommendation=(
            "PRIOR PATTERN DETECTED. Increase scrutiny / require deterministic security evaluation."
        ),
    )

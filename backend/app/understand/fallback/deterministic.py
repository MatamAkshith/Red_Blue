"""Deterministic fallback investigation, used when Featherless is
unavailable. No LLM reasoning happens here -- every field is built
straight from the already-determined P1 facts in the evidence package
(app.understand.evidence.extractor.build_prompt_evidence output), with
plain templated text rather than sophisticated language. This exists only
to keep Blackbox functional without the LLM; it is not a substitute for
Featherless's investigation quality.

Every field explicitly distinguishes three things a reader must not
confuse:

- CONFIRMED EVIDENCE -- facts P1 already determined (event types, trust
  levels, tagged evidence categories, permissions, sensitive resources,
  blast radius). Stated plainly, labeled "Confirmed:".
- DETERMINISTIC INFERENCE -- a small number of fixed, explainable rules
  applied to that evidence (e.g. "the first DECISION event in the attack
  path is flagged as the critical decision"). Labeled "Deterministic
  inference:", never presented as a judgement call.
- UNAVAILABLE AI EXPLANATION -- root_cause/attack_narrative that would
  normally need an LLM's interpretation are explicitly marked as
  unavailable rather than silently faked to look like one.
"""

from __future__ import annotations

from typing import Any

from app.understand.investigation.schemas import (
    CriticalDecision,
    EvidenceInterpretation,
    Investigation,
)

_UNAVAILABLE_NOTICE = (
    "AI explanation unavailable (Featherless unreachable) -- this is a "
    "deterministic fallback built only from confirmed P1 evidence."
)


def _build_root_cause(evidence: dict[str, Any]) -> str:
    incident_type = evidence.get("incident_type", "UNKNOWN")
    return f"[{_UNAVAILABLE_NOTICE}] Confirmed incident_type: {incident_type}."


def _build_attack_narrative(evidence: dict[str, Any]) -> str:
    attack_path = evidence.get("attack_path") or []
    if attack_path:
        body = "Confirmed attack path (event_id sequence): " + " -> ".join(attack_path)
    else:
        body = "Confirmed evidence contains no reconstructed attack path."
    return f"[{_UNAVAILABLE_NOTICE}] {body}"


def _build_critical_decision(evidence: dict[str, Any]) -> CriticalDecision:
    decisions = evidence.get("important_decisions") or []
    attack_path = evidence.get("attack_path") or []

    if decisions:
        return CriticalDecision(
            event_id=decisions[0]["event_id"],
            explanation=(
                "Deterministic inference: first DECISION event in the attack "
                "path, per a fixed rule -- not an AI-assessed critical decision."
            ),
        )
    return CriticalDecision(
        event_id=attack_path[0] if attack_path else "UNKNOWN",
        explanation=(
            "Deterministic inference: no DECISION event in the confirmed "
            "evidence; defaulting to the first event in the attack path."
        ),
    )


def _build_evidence_interpretation(evidence: dict[str, Any]) -> list[EvidenceInterpretation]:
    tagged = (evidence.get("trust_boundary_crossings") or []) + (
        evidence.get("external_destinations") or []
    )
    return [
        EvidenceInterpretation(
            event_id=item["event_id"],
            interpretation=(
                f"Confirmed evidence ({item.get('category', 'tagged')}): "
                f"{item.get('description', '')}"
            ),
        )
        for item in tagged
    ]


def _build_contributing_factors(evidence: dict[str, Any]) -> list[str]:
    trust_crossings = evidence.get("trust_boundary_crossings") or []
    sensitive = evidence.get("sensitive_resources_accessed") or []
    external = evidence.get("external_destinations") or []
    blast_radius = evidence.get("blast_radius") or {}

    factors: list[str] = []
    if trust_crossings:
        factors.append(f"Confirmed: {len(trust_crossings)} trust boundary crossing(s) in evidence")
    if sensitive:
        resources = ", ".join(r["resource"] for r in sensitive)
        factors.append(f"Confirmed: sensitive resources accessed: {resources}")
    if external:
        factors.append(f"Confirmed: {len(external)} external transmission event(s) in evidence")
    if blast_radius.get("risk_score"):
        factors.append(f"Confirmed: AEGIS risk_score = {blast_radius['risk_score']}")
    if not factors:
        factors.append("Confirmed: no tagged evidence categories present in this package")
    return factors


def fallback_investigation(evidence: dict[str, Any]) -> Investigation:
    return Investigation(
        root_cause=_build_root_cause(evidence),
        attack_narrative=_build_attack_narrative(evidence),
        critical_decision=_build_critical_decision(evidence),
        evidence_interpretation=_build_evidence_interpretation(evidence),
        # 0.0 signals "no AI confidence assessment was made", not "zero
        # confidence in the underlying evidence" -- the confirmed facts
        # above stand on their own regardless of this number.
        confidence=0.0,
        contributing_factors=_build_contributing_factors(evidence),
        failure_pattern_candidate=None,
    )

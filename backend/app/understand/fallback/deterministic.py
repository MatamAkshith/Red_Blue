"""Deterministic fallback investigation, used when Featherless is
unavailable. No LLM reasoning happens here -- every field is built
straight from the already-determined P1 facts in the evidence package
(app.understand.evidence.extractor.build_prompt_evidence output), with
plain templated text rather than sophisticated language. This exists only
to keep Blackbox functional without the LLM; it is not a substitute for
Featherless's investigation quality.

The prose fields (root_cause, attack_narrative) are rendered as three
explicitly labeled sections so a reader never has to guess which kind of
claim they're looking at:

CONFIRMED:
    Facts P1 already determined (event types, trust levels, tagged
    evidence categories, permissions, sensitive resources, blast radius),
    stated plainly -- no interpretation added.

DETERMINISTIC INFERENCE:
    A small number of fixed, explainable rules applied to those facts
    (e.g. "sensitive resource access + an external destination in the same
    evidence package" implies "sensitive data reached an external
    destination"). Never presented as a judgement call, and never
    dependent on anything but the supplied evidence.

AI EXPLANATION:
    Always literally "Unavailable" here -- this module must never
    fabricate AI reasoning or claim an LLM explanation exists. If you're
    reading this section and it says anything else, that's a bug.
"""

from __future__ import annotations

from typing import Any

from app.understand.investigation.schemas import (
    CriticalDecision,
    EvidenceInterpretation,
    Investigation,
)

_AI_EXPLANATION_UNAVAILABLE = (
    "Unavailable -- Featherless could not be reached. This is a "
    "deterministic-only report built solely from confirmed P1 evidence; "
    "no AI reasoning was performed and none is claimed here."
)


def _report(confirmed: list[str], inference: list[str]) -> str:
    confirmed_block = " ".join(confirmed) or "No confirmed facts available in this evidence package."
    inference_block = " ".join(inference) or "No deterministic inference could be drawn from this evidence."
    return (
        f"CONFIRMED:\n{confirmed_block}\n\n"
        f"DETERMINISTIC INFERENCE:\n{inference_block}\n\n"
        f"AI EXPLANATION:\n{_AI_EXPLANATION_UNAVAILABLE}"
    )


def _build_root_cause(evidence: dict[str, Any]) -> str:
    incident_type = evidence.get("incident_type", "UNKNOWN")
    confirmed = [f"Incident type confirmed by P1 as {incident_type}."]

    trust_crossings = evidence.get("trust_boundary_crossings") or []
    inference = (
        [
            f"{len(trust_crossings)} confirmed trust boundary crossing(s) in the "
            "evidence suggest untrusted input influenced agent behavior."
        ]
        if trust_crossings
        else []
    )
    return _report(confirmed, inference)


def _build_attack_narrative(evidence: dict[str, Any]) -> str:
    attack_path = evidence.get("attack_path") or []
    confirmed = (
        [f"Agent behavior followed confirmed event sequence: {' -> '.join(attack_path)}."]
        if attack_path
        else ["P1 did not reconstruct an attack path for this evidence."]
    )

    sensitive = evidence.get("sensitive_resources_accessed") or []
    external = evidence.get("external_destinations") or []
    if sensitive:
        resources = ", ".join(r["resource"] for r in sensitive)
        confirmed.append(f"Agent accessed confirmed sensitive resource(s): {resources}.")

    inference: list[str] = []
    if sensitive and external:
        inference.append("Sensitive data reached an external destination.")
    elif external:
        inference.append("Agent activity reached an external destination.")

    return _report(confirmed, inference)


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
        # above stand on their own regardless of this number. This is the
        # only value that's ever appropriate here: the fallback path never
        # runs an LLM, so there is nothing to score confidence in.
        confidence=0.0,
        contributing_factors=_build_contributing_factors(evidence),
        failure_pattern_candidate=None,
    )

"""Checkpoint 3 -- fact vs. interpretation. Makes the P1-fact /
LLM-interpretation boundary explicit and verifies it holds end to end.

CONFIRMED FACT lives only in IncidentAnalysis / the evidence package built
from it (app.understand.evidence.extractor.build_prompt_evidence) -- P1's
domain.

LLM INTERPRETATION lives only in Investigation -- root_cause,
attack_narrative, and contributing_factors are free-text synthesis with no
structural claim to being a raw fact; critical_decision and
evidence_interpretation are the only fields that cite a specific event_id,
and Checkpoint 2's provenance check (FeatherlessClient._validate_provenance)
guarantees every such citation is real, not fabricated.
"""

from __future__ import annotations

import json

from backend.app.core.config import Settings
from backend.app.understand.evidence.extractor import build_prompt_evidence
from backend.app.understand.fallback.deterministic import fallback_investigation
from backend.app.understand.featherless.client import FeatherlessClient
from backend.app.understand.investigation.investigator import investigate
from backend.app.understand.investigation.schemas import Investigation
from tests.test_contracts import make_incident
from tests.test_featherless_client import fake_completion


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def test_p1_facts_remain_authoritative_and_untouched_by_investigation():
    incident = make_incident()
    before = incident.model_dump(mode="json")

    fallback_investigation(build_prompt_evidence(incident))

    after = incident.model_dump(mode="json")
    assert before == after  # nothing about investigating an incident mutates it


def test_llm_output_has_no_field_that_could_pass_as_a_p1_fact():
    # If Investigation had e.g. an `events` or `blast_radius` field, an LLM
    # response could be mistaken for -- or used in place of -- the real P1
    # data. It doesn't: the only fields that name specific evidence
    # (critical_decision, evidence_interpretation) point *at* evidence by
    # event_id, they don't restate or replace it.
    p1_only_fields = {"events", "attack_path", "permissions", "sensitive_resources", "blast_radius"}
    assert not set(Investigation.model_fields) & p1_only_fields


def test_llm_cannot_overwrite_p1_evidence_via_the_full_pipeline(monkeypatch):
    incident = make_incident()
    original_attack_path = incident.attack_path  # frozen tuple -- safe to alias, not copy

    payload = {
        "root_cause": "an LLM's claim",
        "attack_narrative": "an LLM's narrative",
        "critical_decision": {"event_id": "E15", "explanation": "x"},
        "evidence_interpretation": [],
        "confidence": 0.5,
        "contributing_factors": [],
        "failure_pattern_candidate": None,
    }
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(payload)),
    )

    investigate(incident, settings=make_settings(), client=client)

    # The incident -- P1's security truth -- is exactly what it was before,
    # regardless of what the LLM said.
    assert incident.attack_path == original_attack_path


def test_conclusions_can_reference_evidence_by_event_id(monkeypatch):
    incident = make_incident()
    evidence = build_prompt_evidence(incident)

    payload = {
        "root_cause": "x",
        "attack_narrative": "y",
        "critical_decision": {"event_id": "E15", "explanation": "z"},
        "evidence_interpretation": [
            {"event_id": "E14", "interpretation": "untrusted source"}
        ],
        "confidence": 0.9,
        "contributing_factors": [],
        "failure_pattern_candidate": None,
    }
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(payload)),
    )

    result = client.analyze(evidence)
    assert result.critical_decision.event_id == "E15"
    assert result.evidence_interpretation[0].event_id == "E14"


def test_unsupported_prose_fields_carry_no_false_grounding_claim():
    # root_cause / attack_narrative / contributing_factors are plain
    # str/list[str] -- they have no event_id to point at, so they can
    # never masquerade as a provenance-checked claim the way
    # critical_decision/evidence_interpretation do (those two are the only
    # fields Checkpoint 2's provenance gate validates against real
    # event_ids). This documents that boundary structurally, not by
    # convention.
    fields = Investigation.model_fields
    assert fields["root_cause"].annotation is str
    assert fields["attack_narrative"].annotation is str
    assert fields["contributing_factors"].annotation == list[str]


def test_fallback_results_are_exempt_from_llm_provenance_checking_by_design():
    # The fallback's own event_id choices come directly from evidence (or
    # the honest "UNKNOWN" sentinel when none exists) -- it never invents
    # anything, so it doesn't need to go through FeatherlessClient's
    # provenance gate, which exists specifically to police untrusted LLM
    # output.
    result = fallback_investigation({})
    assert result.critical_decision.event_id == "UNKNOWN"
    assert result.confidence == 0.0

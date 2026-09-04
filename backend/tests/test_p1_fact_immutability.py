"""Checkpoint 5 -- P1 security fact immutability. CRITICAL security
checkpoint.

Prior checkpoints proved the LLM has no field in its own output that could
carry severity/attack_path/blast_radius/permissions/sensitive_resources
(Checkpoint 1/3), and that investigate() never writes back to the incident
object (Checkpoint 3). This checkpoint closes the remaining gap: nothing
previously stopped *any* code from directly reassigning or in-place
mutating those fields on the IncidentAnalysis object itself, which would
have been true regardless of what Featherless said. IncidentAnalysis and
its nested BlastRadius/PermissionFact/SensitiveResource models are now
frozen (Pydantic model_config=ConfigDict(frozen=True)), and attack_path/
permissions/sensitive_resources are tuples, not lists, so neither
reassignment nor in-place mutation is possible.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from backend.app.aegis.blast_radius import Severity
from backend.app.contracts.incident_analysis import (
    BlastRadius,
    IncidentAnalysis,
    IncidentSeverity,
    PermissionFact,
    SensitiveResource,
)
from backend.app.core.config import Settings
from backend.app.understand.featherless.client import FeatherlessClient
from backend.app.understand.investigation.investigator import investigate
from backend.app.understand.investigation.schemas import Investigation
from tests.test_contracts import make_incident
from tests.test_featherless_client import fake_completion


def make_settings(api_key: str | None = "test-key") -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key=api_key,
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


# --- direct mutation attempts are rejected at the type level -----------


def test_severity_cannot_be_reassigned():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.severity = IncidentSeverity.CRITICAL


def test_attack_path_cannot_be_reassigned():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.attack_path = ("FAKE_EVENT",)


def test_attack_path_cannot_be_mutated_in_place():
    incident = make_incident()
    # tuples have no .append/.remove/__setitem__ -- this must fail at the
    # object level, not just be blocked by a convention.
    with pytest.raises(AttributeError):
        incident.attack_path.append("FAKE_EVENT")
    with pytest.raises(TypeError):
        incident.attack_path[0] = "FAKE_EVENT"


def test_blast_radius_cannot_be_reassigned():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.blast_radius = BlastRadius(risk_score=0.0)


def test_blast_radius_fields_cannot_be_mutated_in_place():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.blast_radius.risk_score = 0.0
    with pytest.raises(AttributeError):
        incident.blast_radius.reachable_sensitive_resources.append("FAKE")


def test_permissions_cannot_be_reassigned_or_mutated():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.permissions = ()
    with pytest.raises(AttributeError):
        incident.permissions.append(
            PermissionFact(event_id="E1", resource="x", permission="x", granted=True)
        )
    with pytest.raises(ValidationError):
        incident.permissions[0].granted = False


def test_sensitive_resources_cannot_be_reassigned_or_mutated():
    incident = make_incident()
    with pytest.raises(ValidationError):
        incident.sensitive_resources = ()
    with pytest.raises(AttributeError):
        incident.sensitive_resources.append(
            SensitiveResource(resource="x", severity=Severity.PUBLIC)
        )
    with pytest.raises(ValidationError):
        incident.sensitive_resources[0].severity = Severity.PUBLIC


# --- malicious/contradictory LLM output cannot alter P1 facts ----------


def _investigation_payload(**overrides) -> dict:
    payload = {
        "root_cause": "x",
        "attack_narrative": "y",
        "critical_decision": {"event_id": "E15", "explanation": "z"},
        "evidence_interpretation": [],
        "confidence": 0.9,
        "contributing_factors": [],
        "failure_pattern_candidate": None,
    }
    payload.update(overrides)
    return payload


def test_llm_response_has_no_field_that_could_carry_a_p1_fact():
    # A "malicious" LLM response can only ever be shaped like an
    # Investigation -- it structurally cannot contain severity, attack_path,
    # permissions, sensitive_resources, or blast_radius, so there's nothing
    # for FeatherlessClient to even mistakenly apply.
    malicious_shaped_payload = _investigation_payload(
        severity="CRITICAL",
        attack_path=["FAKE1", "FAKE2"],
        blast_radius={"risk_score": 999.0},
        permissions=[{"event_id": "E1", "resource": "x", "permission": "x", "granted": True}],
        sensitive_resources=[{"resource": "x", "severity": "CRITICAL"}],
    )
    # Extra keys a strict LLM might add are simply ignored by
    # Investigation's schema -- they never reach an IncidentAnalysis field.
    result = Investigation.model_validate(malicious_shaped_payload)
    assert not hasattr(result, "severity")
    assert not hasattr(result, "attack_path")
    assert not hasattr(result, "blast_radius")
    assert not hasattr(result, "permissions")
    assert not hasattr(result, "sensitive_resources")


def test_contradictory_llm_output_does_not_alter_the_incident_through_the_full_pipeline(
    monkeypatch,
):
    incident = make_incident()
    original_severity = incident.severity
    original_attack_path = incident.attack_path
    original_blast_radius = incident.blast_radius
    original_permissions = incident.permissions
    original_sensitive_resources = incident.sensitive_resources

    # A response that *claims* things contradicting P1 (in prose, since
    # there's no field to put them in structurally) -- this is the
    # "malicious/contradictory" case the checkpoint asks to prove is inert.
    contradictory_payload = _investigation_payload(
        root_cause="Actually severity is LOW and nothing sensitive was touched",
        attack_narrative="The blast radius is zero and no permissions were used",
    )
    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(contradictory_payload)),
    )

    investigate(incident, settings=make_settings(), client=client)

    assert incident.severity == original_severity
    assert incident.attack_path == original_attack_path
    assert incident.blast_radius == original_blast_radius
    assert incident.permissions == original_permissions
    assert incident.sensitive_resources == original_sensitive_resources


def test_original_incident_object_identity_and_facts_survive_investigation(monkeypatch):
    # Belt-and-braces: same object, same facts, before and after, whether
    # Featherless succeeds or fails.
    incident = make_incident()

    client = FeatherlessClient(make_settings())
    monkeypatch.setattr(
        client._client.chat.completions,
        "create",
        lambda **kwargs: fake_completion(json.dumps(_investigation_payload())),
    )
    investigate(incident, settings=make_settings(), client=client)
    assert incident.severity == IncidentSeverity.CRITICAL
    assert incident.blast_radius.risk_score == 8.5

    # And again via the deterministic fallback path.
    investigate(incident, settings=make_settings(api_key=None))
    assert incident.severity == IncidentSeverity.CRITICAL
    assert incident.blast_radius.risk_score == 8.5

import pytest

from backend.app.aegis.blast_radius import Severity
from backend.app.contracts.incident_analysis import (
    BlastRadius,
    IncidentAnalysis,
    IncidentSeverity,
    SensitiveResource,
)
from backend.app.memory.patterns import (
    FailurePatternStore,
    PatternProvenance,
)
from backend.app.memory.protection import ProtectionSignal, check_future_protection
from backend.app.understand.investigation.schemas import FailurePatternCandidate


@pytest.fixture
def memory_store(tmp_path):
    db_file = tmp_path / "test_patterns.db"
    return FailurePatternStore(db_file)


def test_check_future_protection_match(memory_store):
    signature = "INDIRECT_PROMPT_INJECTION|customer_pii|external=True"
    candidate = FailurePatternCandidate(
        pattern_name="Indirect Injection Exfil",
        description="Malicious prompt injection extracting PII to external endpoint",
        indicators=("INDIRECT_PROMPT_INJECTION", "customer_pii"),
    )
    provenance = PatternProvenance(
        incident_id="INC-PRIOR-101",
        session_id="SES-PRIOR-500",
        finding_ids=("F1", "F2"),
        event_ids=("E1", "E2", "E3"),
    )
    memory_store.remember(signature, candidate, provenance)

    incident = IncidentAnalysis(
        incident_id="INC-NEW-202",
        agent_id="agent_007",
        session_id="SES-NEW-600",
        incident_type="INDIRECT_PROMPT_INJECTION",
        severity=IncidentSeverity.CRITICAL,
        sensitive_resources=[
            SensitiveResource(resource="customer_pii", severity=Severity.CRITICAL)
        ],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=("customer_pii",),
            reachable_external_destinations=("https://external-exfil.com",),
        ),
    )

    signal = check_future_protection(incident, memory_store)

    assert signal is not None
    assert isinstance(signal, ProtectionSignal)
    assert signal.matched is True
    assert signal.pattern_signature == signature
    assert signal.prior_incident_id == "INC-PRIOR-101"
    assert signal.prior_session_id == "SES-PRIOR-500"
    assert "PRIOR PATTERN DETECTED" in signal.recommendation.upper()


def test_check_future_protection_no_match(memory_store):
    signature = "INDIRECT_PROMPT_INJECTION|customer_pii|external=True"
    candidate = FailurePatternCandidate(
        pattern_name="Indirect Injection Exfil",
        description="Malicious prompt injection extracting PII to external endpoint",
        indicators=("INDIRECT_PROMPT_INJECTION",),
    )
    provenance = PatternProvenance(
        incident_id="INC-PRIOR-101",
        session_id="SES-PRIOR-500",
    )
    memory_store.remember(signature, candidate, provenance)

    unrelated_incident = IncidentAnalysis(
        incident_id="INC-NEW-303",
        agent_id="agent_007",
        session_id="SES-NEW-700",
        incident_type="PRIVILEGE_VIOLATION",
        severity=IncidentSeverity.LOW,
        sensitive_resources=[],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=(),
            reachable_external_destinations=(),
        ),
    )

    signal = check_future_protection(unrelated_incident, memory_store)
    assert signal is None


def test_check_future_protection_isolation(memory_store):
    signature = "INDIRECT_PROMPT_INJECTION|customer_pii|external=True"
    candidate = FailurePatternCandidate(
        pattern_name="Indirect Injection Exfil",
        description="Malicious prompt injection extracting PII to external endpoint",
        indicators=("INDIRECT_PROMPT_INJECTION",),
    )
    provenance = PatternProvenance(
        incident_id="INC-PRIOR-101",
        session_id="SES-PRIOR-500",
    )
    memory_store.remember(signature, candidate, provenance)

    incident = IncidentAnalysis(
        incident_id="INC-NEW-202",
        agent_id="agent_007",
        session_id="SES-NEW-600",
        incident_type="INDIRECT_PROMPT_INJECTION",
        severity=IncidentSeverity.CRITICAL,
        sensitive_resources=[
            SensitiveResource(resource="customer_pii", severity=Severity.CRITICAL)
        ],
        blast_radius=BlastRadius(
            reachable_sensitive_resources=("customer_pii",),
            reachable_external_destinations=("https://external-exfil.com",),
        ),
    )

    snapshot_before = incident.model_dump()
    signal = check_future_protection(incident, memory_store)
    snapshot_after = incident.model_dump()

    assert signal is not None
    assert snapshot_before == snapshot_after

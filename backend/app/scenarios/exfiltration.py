"""Controlled indirect-prompt-injection -> exfiltration scenario.

    malicious document -> RAG retrieval -> indirect prompt injection
    -> agent decision -> CRM tool -> sensitive customer data -> external email

Expressed entirely with the existing AgentEvent contract. No new event
schema, no new graph, no new impact model.
"""

from __future__ import annotations

from app.aegis.blast_radius import Severity
from app.contracts.incident_analysis import SensitiveResource
from app.events.schemas import AgentEvent
from app.scenarios.demo_agent import AGENT_ID, SESSION_ID, run_demo_attack

# Deterministic asset inventory. Sensitivity is declared here, never
# inferred from events by AEGIS.
SENSITIVE_REGISTRY: tuple[SensitiveResource, ...] = (
    SensitiveResource(
        resource="crm://sensitive_customer_records",
        severity=Severity.SENSITIVE,
        resource_type="customer_pii",
    ),
    SensitiveResource(
        resource="db://internal_billing",
        severity=Severity.INTERNAL,
        resource_type="billing",
    ),
)


def build_exfiltration_events(
    *, include_malicious_branch: bool = True
) -> list[AgentEvent]:
    """The scenario trace, produced by the controlled demo agent.

    ``include_malicious_branch=False`` yields the benign prefix only --
    used by CHIMERA to re-run the attack after an intervention.
    """

    return run_demo_attack(include_malicious_branch=include_malicious_branch)


__all__ = ["AGENT_ID", "SENSITIVE_REGISTRY", "SESSION_ID", "build_exfiltration_events"]

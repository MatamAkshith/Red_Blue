"""Controlled attack scenarios expressed purely as AgentEvents."""

from .exfiltration import (
    SENSITIVE_REGISTRY,
    build_exfiltration_events,
)

__all__ = ["SENSITIVE_REGISTRY", "build_exfiltration_events"]

"""Controlled attack scenarios expressed purely as AgentEvents."""

from .demo_agent import AGENT_ID, SESSION_ID, DemoAgent, run_demo_attack
from .exfiltration import SENSITIVE_REGISTRY, build_exfiltration_events

__all__ = [
    "AGENT_ID",
    "SESSION_ID",
    "SENSITIVE_REGISTRY",
    "DemoAgent",
    "build_exfiltration_events",
    "run_demo_attack",
]

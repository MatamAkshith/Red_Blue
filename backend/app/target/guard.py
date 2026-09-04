"""Task P3 — BLACKBOX Enforcement Guard for Target Agent Policy Enforcement.

Provides runtime enforcement of active security intervention rules
(BLOCK_EXTERNAL_DESTINATION, BLOCK_RESOURCE, BLOCK_TOOL, KILL_AGENT)
at the target agent action execution boundary.
"""

from __future__ import annotations

from typing import Collection
from backend.app.intervention.models import Intervention, InterventionType


class EnforcementGuard:
    """Active security enforcement guard for target agent runtime environment."""

    def __init__(self, interventions: Collection[Intervention] = ()):
        self._active_interventions: list[Intervention] = list(interventions)

    def install(self, intervention: Intervention | None) -> None:
        """Install/activate an intervention policy rule."""
        if intervention and intervention not in self._active_interventions:
            self._active_interventions.append(intervention)

    def clear(self) -> None:
        """Clear all active intervention rules."""
        self._active_interventions.clear()

    @property
    def active_interventions(self) -> list[Intervention]:
        return list(self._active_interventions)

    def is_blocked(
        self,
        *,
        destination: str | None = None,
        resource: str | None = None,
        tool: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[bool, Intervention | None, str]:
        """Check if an intended action/resource/tool/agent is blocked by active policy rules.

        Returns (is_blocked, blocking_intervention, reason_string).
        """
        for rule in self._active_interventions:
            t = rule.intervention_type
            v = rule.value

            # 1. BLOCK_EXTERNAL_DESTINATION
            if t == InterventionType.BLOCK_EXTERNAL_DESTINATION and destination:
                if destination == v or (v and v in destination) or (destination and destination in v):
                    return (
                        True,
                        rule,
                        f"External destination '{destination}' blocked by policy rule: {rule.description}",
                    )

            # 2. BLOCK_RESOURCE
            if t == InterventionType.BLOCK_RESOURCE and resource:
                if resource == v or (v and v in resource) or (resource and resource in v):
                    return (
                        True,
                        rule,
                        f"Sensitive resource '{resource}' blocked by policy rule: {rule.description}",
                    )

            # 3. BLOCK_TOOL
            if t == InterventionType.BLOCK_TOOL and tool:
                if tool == v or (v and v in tool) or (tool and tool in v):
                    return (
                        True,
                        rule,
                        f"Tool/Target '{tool}' access blocked by policy rule: {rule.description}",
                    )

            # 4. KILL_AGENT
            if t == InterventionType.KILL_AGENT and agent_id:
                if agent_id == v or (v and v in agent_id) or (agent_id and agent_id in v):
                    return (
                        True,
                        rule,
                        f"Agent '{agent_id}' execution terminated by policy rule: {rule.description}",
                    )

        return False, None, ""


_GLOBAL_GUARD = EnforcementGuard()


def get_global_enforcement_guard() -> EnforcementGuard:
    """Retrieve global process-wide enforcement guard singleton."""
    return _GLOBAL_GUARD

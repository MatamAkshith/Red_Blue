"""Task 6, 7, 8 — AgentEvent Adapter for Live Target Agent Telemetry.

Translates observable target Email Processing Agent operational steps into authoritative
Universal AgentEvents, establishing parent-child causal lineage and submitting them
through BLACKBOX's existing EventCollector / POST /events pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from backend.app.events.collector import EventCollector, EventValidationError
from backend.app.events.schemas import AgentEvent, EventType, TrustLevel
from backend.app.target.email_agent import AgentStep


class AgentEventAdapter:
    """Translates EmailProcessingAgent steps into AgentEvents and ingests them into BLACKBOX."""

    def __init__(
        self,
        collector: EventCollector | None = None,
        *,
        submit_fn: Callable[[dict[str, Any]], Any] | None = None,
        session_id: str = "S-LIVE-DEMO-1",
        agent_id: str = "agent-email-processor",
        demo_delay_seconds: float = 0.0,
        event_id_prefix: str = "E",
    ) -> None:
        self.collector = collector
        self.submit_fn = submit_fn
        self.session_id = session_id
        self.agent_id = agent_id
        self.demo_delay_seconds = demo_delay_seconds
        self.event_id_prefix = event_id_prefix

        self.last_event_id: str | None = None
        self.event_counter: int = 0
        self.emitted_events: list[AgentEvent] = []

    def reset(self, session_id: str | None = None) -> None:
        """Reset internal sequence state for a new session."""
        if session_id:
            self.session_id = session_id
        self.last_event_id = None
        self.event_counter = 0
        self.emitted_events.clear()

    def translate_step_to_event_dict(self, step: AgentStep) -> dict[str, Any]:
        """Convert a target AgentStep into an authoritative AgentEvent dictionary."""
        self.event_counter += 1
        event_id = f"{self.event_id_prefix}{self.event_counter}"

        # Step mapping rules per BLACKBOX contracts
        parent_id = self.last_event_id
        event_type_str = step.event_type.upper()
        trust_level_str = "TRUSTED" if step.source in ("user", "agent") and event_type_str != "ACTION" else "UNTRUSTED"
        if step.event_type == "RETRIEVAL" or step.source == "untrusted":
            trust_level_str = "UNTRUSTED"

        raw_dict: dict[str, Any] = {
            "event_id": event_id,
            "parent_event_id": parent_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "event_type": event_type_str,
            "source": step.source,
            "target": step.target,
            "resource": step.resource,
            "action": step.action,
            "permission": step.permission,
            "trust_level": trust_level_str,
            "timestamp": step.timestamp.isoformat(),
            "metadata": step.details,
        }

        self.last_event_id = event_id
        return raw_dict

    def handle_step(self, step: AgentStep) -> AgentEvent:
        """Process an emitted agent step, translate it, and submit to BLACKBOX ingestion."""
        if self.demo_delay_seconds > 0:
            time.sleep(self.demo_delay_seconds)

        raw_event = self.translate_step_to_event_dict(step)

        if self.submit_fn:
            # Custom submit function (e.g. FastAPI TestClient POST /events)
            result = self.submit_fn(raw_event)
            if isinstance(result, AgentEvent):
                event = result
            else:
                event = AgentEvent.model_validate(result)
        elif self.collector:
            # In-process EventCollector submission
            event = self.collector.submit(raw_event)
        else:
            # Standalone validation without persistence if no collector specified
            event = AgentEvent.model_validate(raw_event)

        self.emitted_events.append(event)
        return event

    def create_listener(self) -> Callable[[AgentStep], None]:
        """Return callback for EmailProcessingAgent.step_listener."""
        return self.handle_step

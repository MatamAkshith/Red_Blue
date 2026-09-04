from __future__ import annotations

from typing import Any

from backend.app.events.schemas import AgentEvent, EventType, TrustLevel


class BlackboxObserver:
    """Stateful agent observer layer for capturing real-time AI agent behavior
    and producing canonical AgentEvent streams with causal lineage parent tracking.
    """

    def __init__(self, session_id: str, agent_id: str) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        self.current_parent_id: str | None = None
        self._event_counter = 0

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        return f"E{self._event_counter}"

    def _create_event(
        self,
        event_type: EventType,
        source: str,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        permission: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.UNKNOWN,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        event_id = self._generate_event_id()
        parent_id = self.current_parent_id

        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)

        event = AgentEvent(
            event_id=event_id,
            parent_event_id=parent_id,
            session_id=self.session_id,
            agent_id=self.agent_id,
            event_type=event_type,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            trust_level=trust_level,
            metadata=metadata if metadata is not None else {},
        )

        self.current_parent_id = event_id
        return event

    def on_input(
        self,
        source: str,
        resource: str | None = None,
        action: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.TRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.INPUT,
            source=source,
            resource=resource,
            action=action,
            trust_level=trust_level,
            metadata=metadata,
        )

    def on_retrieval(
        self,
        source: str,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        permission: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.UNTRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.RETRIEVAL,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            trust_level=trust_level,
            metadata=metadata,
        )

    def on_decision(
        self,
        source: str,
        action: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.TRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.DECISION,
            source=source,
            action=action,
            trust_level=trust_level,
            metadata=metadata,
        )

    def on_tool_call(
        self,
        source: str,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        permission: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.TRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.TOOL_CALL,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            trust_level=trust_level,
            metadata=metadata,
        )

    def on_tool_result(
        self,
        source: str,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.TRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.TOOL_RESULT,
            source=source,
            target=target,
            resource=resource,
            action=action,
            trust_level=trust_level,
            metadata=metadata,
        )

    def on_action(
        self,
        source: str,
        target: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        permission: str | None = None,
        trust_level: TrustLevel | str = TrustLevel.TRUSTED,
        metadata: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return self._create_event(
            event_type=EventType.ACTION,
            source=source,
            target=target,
            resource=resource,
            action=action,
            permission=permission,
            trust_level=trust_level,
            metadata=metadata,
        )

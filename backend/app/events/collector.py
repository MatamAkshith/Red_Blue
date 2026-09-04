from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from backend.app.events.schemas import AgentEvent
from backend.app.events.storage import EventStore


class EventValidationError(Exception):
    def __init__(self, errors: list[dict[str, Any]]):
        self.errors = errors
        super().__init__(f"invalid agent event: {errors}")


class EventCollector:
    """Entry point for untrusted agent events. Every event is validated
    against the Universal AgentEvent schema before it is ever persisted or
    handed to any downstream module."""

    def __init__(self, store: EventStore):
        self._store = store

    def submit(self, raw_event: dict[str, Any]) -> AgentEvent:
        try:
            event = AgentEvent.model_validate(raw_event)
        except ValidationError as exc:
            raise EventValidationError(exc.errors()) from exc
        self._store.append(event)
        return event

    def get_session(self, session_id: str) -> list[AgentEvent]:
        return self._store.get_by_session(session_id)

    def get_sessions(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._store.get_sessions(limit=limit)

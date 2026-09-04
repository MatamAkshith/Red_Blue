from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from backend.app.events.collector import EventCollector, EventValidationError
from backend.app.events.schemas import AgentEvent
from backend.app.events.storage import EventStore
from backend.app.core.config import get_settings

router = APIRouter(prefix="/events", tags=["events"])

_settings = get_settings()
_store = EventStore(_settings.db_path)
_collector = EventCollector(_store)


@router.post("", response_model=AgentEvent)
def submit_event(raw_event: dict[str, Any]) -> AgentEvent:
    try:
        return _collector.submit(raw_event)
    except EventValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors) from exc


@router.get("", response_model=list[AgentEvent])
def list_events(session_id: str = Query(...)) -> list[AgentEvent]:
    return _collector.get_session(session_id)

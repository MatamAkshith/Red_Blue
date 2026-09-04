from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from backend.app.events.collector import EventCollector, EventValidationError
from backend.app.events.schemas import AgentEvent
from backend.app.events.storage import EventStore
from backend.app.core.config import get_settings

from uuid import uuid4
from pydantic import BaseModel, Field
from backend.app.target.runner import run_target_scenario

router = APIRouter(prefix="/events", tags=["events"])

_settings = get_settings()
_store = EventStore(_settings.db_path)
_collector = EventCollector(_store)


class RunDemoRequest(BaseModel):
    scenario: str = Field(default="malicious", description="Scenario type ('malicious' or 'benign')")
    session_id: str | None = Field(default=None, description="Optional custom session ID")
    demo_delay: float = Field(default=0.6, description="Delay between events in seconds for live demonstration pacing")
    async_run: bool = Field(default=True, description="Run target agent in background for live polling demo")


@router.post("", response_model=AgentEvent)
def submit_event(raw_event: dict[str, Any]) -> AgentEvent:
    try:
        return _collector.submit(raw_event)
    except EventValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors) from exc


@router.get("/sessions", response_model=list[dict[str, Any]])
def list_sessions(limit: int = Query(default=10, ge=1, le=100)) -> list[dict[str, Any]]:
    """Returns recent sessions ordered by last event timestamp."""
    return _collector.get_sessions(limit=limit)


@router.get("", response_model=list[AgentEvent])
def list_events(session_id: str = Query(...)) -> list[AgentEvent]:
    return _collector.get_session(session_id)


@router.post("/run-demo")
def trigger_demo_scenario(
    request: RunDemoRequest = RunDemoRequest(),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> dict[str, Any]:
    """Triggers the target EmailProcessingAgent live scenario and ingests AgentEvents into EventStore."""
    session_id = request.session_id or f"S-LIVE-{uuid4().hex[:6]}"

    if request.async_run:
        background_tasks.add_task(
            run_target_scenario,
            scenario=request.scenario,
            live=True,
            collector=_collector,
            session_id=session_id,
            demo_delay=request.demo_delay,
        )
        return {
            "session_id": session_id,
            "scenario": request.scenario,
            "status": "started",
            "demo_delay": request.demo_delay,
            "async_run": True,
        }

    result, events = run_target_scenario(
        scenario=request.scenario,
        live=True,
        collector=_collector,
        session_id=session_id,
        demo_delay=request.demo_delay,
    )
    return {
        "session_id": session_id,
        "scenario": request.scenario,
        "status": result.status,
        "event_count": len(events),
        "events": [ev.model_dump(mode="json") for ev in events],
        "async_run": False,
    }


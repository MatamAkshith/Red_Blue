import sqlite3

import pytest

from backend.app.events.schemas import AgentEvent, EventType
from backend.app.events.storage import EventStore


@pytest.fixture
def store(tmp_path):
    return EventStore(tmp_path / "test.db")


def make_event(event_id: str, session_id: str = "S1") -> AgentEvent:
    return AgentEvent(
        event_id=event_id,
        session_id=session_id,
        agent_id="A1",
        event_type=EventType.ACTION,
        source="agent",
    )


def test_append_and_get_by_session(store):
    e1 = make_event("E1")
    e2 = make_event("E2")
    store.append(e1)
    store.append(e2)

    events = store.get_by_session("S1")
    assert [e.event_id for e in events] == ["E1", "E2"]


def test_sessions_are_isolated(store):
    store.append(make_event("E1", session_id="S1"))
    store.append(make_event("E2", session_id="S2"))

    assert [e.event_id for e in store.get_by_session("S1")] == ["E1"]
    assert [e.event_id for e in store.get_by_session("S2")] == ["E2"]


def test_duplicate_event_id_rejected(store):
    store.append(make_event("E1"))
    with pytest.raises(sqlite3.IntegrityError):
        store.append(make_event("E1"))


def test_unknown_session_returns_empty(store):
    assert store.get_by_session("does-not-exist") == []

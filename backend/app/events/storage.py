from __future__ import annotations

import sqlite3
from pathlib import Path

from app.events.schemas import AgentEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_events_session ON agent_events(session_id);
"""


class EventStore:
    """Append-only store for validated AgentEvents.

    Raw evidence is kept separate from any generated explanation: this store
    only ever holds the validated event payload as received, and events are
    never updated or deleted once written.
    """

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def append(self, event: AgentEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO agent_events (event_id, session_id, payload, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (
                    event.event_id,
                    event.session_id,
                    event.model_dump_json(),
                    event.timestamp.isoformat(),
                ),
            )

    def get_by_session(self, session_id: str) -> list[AgentEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM agent_events WHERE session_id = ? "
                "ORDER BY timestamp ASC",
                (session_id,),
            ).fetchall()
        return [AgentEvent.model_validate_json(row[0]) for row in rows]

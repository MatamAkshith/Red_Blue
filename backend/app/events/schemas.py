from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    INPUT = "INPUT"
    RETRIEVAL = "RETRIEVAL"
    DECISION = "DECISION"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    ACTION = "ACTION"


class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class AgentEvent(BaseModel):
    """Universal AgentEvent — the one frozen contract every Blackbox module
    (execution graph, detection, AEGIS, Understand layer) is built on top of.

    Agent events are untrusted input and must always be validated (i.e.
    parsed through this model) before being used in any analysis.
    """

    event_id: str
    parent_event_id: str | None = None
    session_id: str
    agent_id: str
    event_type: EventType
    source: str
    target: str | None = None
    resource: str | None = None
    action: str | None = None
    permission: str | None = None
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

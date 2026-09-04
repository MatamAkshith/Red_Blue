"""Normalizer — turns raw observer/SDK output into Universal AgentEvents.

STUB: not yet implemented. Once the Blackbox SDK (sdk/observer.py) has a
concrete agent to wrap, this module will convert whatever that adapter
captures (LLM decision, retrieval, tool call/result, sensitive access,
external action) into validated AgentEvent instances handed to
EventCollector.submit().
"""

from __future__ import annotations

from typing import Any

from backend.app.events.schemas import AgentEvent


def normalize(raw: dict[str, Any]) -> AgentEvent:
    raise NotImplementedError("normalizer: pending SDK/observer integration")

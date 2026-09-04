"""Blackbox observer/SDK — wraps a real agent and turns the operations it
performs (LLM/decision event, retrieval, tool call, tool result, sensitive
resource access, external action) into Universal AgentEvents submitted to
the Blackbox event collector:

    Agent -> Observer -> AgentEvent -> Blackbox

For dangerous tools, the observer sits at the control boundary and asks
Blackbox for a decision before the call proceeds:

    Agent -> "call CRM" -> Blackbox security check -> ALLOW/BLOCK/APPROVAL -> CRM

STUB: not yet implemented. This is an adapter interface — the hackathon
target wires one real agent framework to it; more adapters can be added
later (LangGraph, CrewAI, MCP-based agents, custom agents).
"""

from __future__ import annotations

from typing import Any, Protocol


class BlackboxObserver(Protocol):
    def on_input(self, payload: dict[str, Any]) -> None: ...
    def on_retrieval(self, payload: dict[str, Any]) -> None: ...
    def on_decision(self, payload: dict[str, Any]) -> None: ...
    def on_tool_call(self, payload: dict[str, Any]) -> str:
        """Returns ALLOW / BLOCK / REQUIRE_APPROVAL for the requested call."""
        ...
    def on_tool_result(self, payload: dict[str, Any]) -> None: ...
    def on_action(self, payload: dict[str, Any]) -> None: ...

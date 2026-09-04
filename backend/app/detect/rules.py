"""Deterministic detection rules — the security authority.

STUB: not yet implemented. Detection must stay deterministic (trust
boundaries, sensitive resource access, suspicious tool usage, privilege
changes, unexpected data flow, external transmission) — never "ask an LLM
if this is an attack". Operates on the execution graph from app.graph.builder.
"""

from __future__ import annotations


def detect(execution_graph) -> list:
    raise NotImplementedError("detection engine: not yet implemented")

"""AEGIS — impact intelligence: deterministic reachability and blast radius.

STUB: not yet implemented. Severity weights are frozen per the spec; do not
let an LLM compute these values.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    PUBLIC = 1
    INTERNAL = 3
    SENSITIVE = 7
    CRITICAL = 10


def compute_blast_radius(execution_graph, compromised_node) -> dict:
    raise NotImplementedError("AEGIS blast radius: not yet implemented")

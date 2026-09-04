"""Deterministic resource sensitivity weights.

`Severity` is the shared sensitivity vocabulary used by the P1->P2
contracts (`app.contracts.incident_analysis`) and by AEGIS impact
analysis. Blast radius itself is computed by `app.aegis.engine`; there is
no second blast-radius policy in this codebase.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    PUBLIC = 1
    INTERNAL = 3
    SENSITIVE = 7
    CRITICAL = 10

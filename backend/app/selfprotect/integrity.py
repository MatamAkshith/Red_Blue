"""Blackbox self-protection — lightweight integrity monitoring. If
Blackbox's own integrity becomes uncertain, drop into Safe Mode: block
sensitive tools and dangerous external actions, allow low-risk operations,
require approval for high-risk ones.

STUB: not yet implemented.
"""

from __future__ import annotations

from enum import Enum


class IntegrityStatus(str, Enum):
    OK = "OK"
    SAFE_MODE = "SAFE_MODE"


def check_integrity() -> IntegrityStatus:
    raise NotImplementedError("integrity check: not yet implemented")

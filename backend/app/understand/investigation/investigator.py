"""Investigator — orchestrates evidence -> prompt -> Featherless ->
Investigation, falling back to app.understand.fallback.deterministic when
Featherless is unavailable so Blackbox never crashes without it.

STUB: not yet implemented.
"""

from __future__ import annotations

from app.understand.investigation.schemas import Investigation


def investigate(evidence: dict) -> Investigation:
    raise NotImplementedError("investigator: not yet implemented")

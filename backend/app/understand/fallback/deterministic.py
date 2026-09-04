"""Deterministic fallback investigation templates, used when Featherless is
unavailable. No sophisticated language needed — this just keeps Blackbox
functional without the LLM.

STUB: not yet implemented.
"""

from __future__ import annotations

from app.understand.investigation.schemas import Investigation


def fallback_investigation(evidence: dict) -> Investigation:
    raise NotImplementedError("deterministic fallback: not yet implemented")

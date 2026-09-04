"""Adaptive failure-pattern memory."""

from .patterns import (
    FailurePatternStore,
    PatternProvenance,
    StoredPattern,
    compute_signature,
)

__all__ = [
    "FailurePatternStore",
    "PatternProvenance",
    "StoredPattern",
    "compute_signature",
]

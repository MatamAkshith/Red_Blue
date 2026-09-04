"""Adaptive failure-pattern memory and future protection."""

from .patterns import (
    FailurePatternStore,
    PatternProvenance,
    StoredPattern,
    compute_signature,
)
from .protection import ProtectionSignal, check_future_protection

__all__ = [
    "FailurePatternStore",
    "PatternProvenance",
    "StoredPattern",
    "compute_signature",
    "ProtectionSignal",
    "check_future_protection",
]

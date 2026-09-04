"""Featherless configuration — reads from environment only, never hardcoded.
See app.core.config.get_settings() for the actual values (featherless_api_key,
featherless_base_url, featherless_model).
"""

from __future__ import annotations

from app.core.config import Settings, get_settings

__all__ = ["Settings", "get_settings"]

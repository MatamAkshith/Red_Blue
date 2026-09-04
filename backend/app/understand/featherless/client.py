"""FeatherlessClient — thin wrapper over the Featherless OpenAI-compatible
API (https://api.featherless.ai/v1). Blackbox calls this directly; it is not
exposed as an MCP tool.

STUB: not yet implemented. When built, analyze() must validate the model's
JSON response against app.understand.investigation.schemas.Investigation
and never let Featherless invent events, tools, permissions, resources, or
attack steps it wasn't given as evidence.
"""

from __future__ import annotations

from typing import Any

from app.core.config import Settings
from app.understand.investigation.schemas import Investigation


class FeatherlessClient:
    def __init__(self, settings: Settings):
        self._settings = settings

    def analyze(self, evidence: dict[str, Any]) -> Investigation:
        raise NotImplementedError("FeatherlessClient.analyze: not yet implemented")

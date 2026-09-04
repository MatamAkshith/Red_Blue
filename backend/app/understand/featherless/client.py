"""FeatherlessClient — thin wrapper over the Featherless OpenAI-compatible
API (https://api.featherless.ai/v1). This is the only place in Blackbox
that talks to Featherless; no other module should make the API call
directly:

    Investigator -> FeatherlessClient -> Featherless API

Uses the official `openai` Python SDK, since Featherless exposes an
OpenAI-compatible endpoint -- no Featherless-specific SDK needed. The
model name is read from configuration, so swapping which model Featherless
routes to is a config change, not a code change.
"""

from __future__ import annotations

import json
import re
from typing import Any

import openai
from pydantic import ValidationError

from backend.app.core.config import Settings
from backend.app.understand.evidence.extractor import known_event_ids
from backend.app.understand.investigation.prompts import build_investigation_prompt
from backend.app.understand.investigation.schemas import Investigation

_DEFAULT_TIMEOUT_SECONDS = 30.0
_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


class FeatherlessError(Exception):
    """Raised when Featherless is unreachable, errors, times out, or returns
    output that fails schema validation. Messages are always safe to log --
    the API key is never included."""


class FeatherlessClient:
    def __init__(self, settings: Settings, timeout: float = _DEFAULT_TIMEOUT_SECONDS):
        if not settings.featherless_api_key:
            raise FeatherlessError("FEATHERLESS_API_KEY is not configured")
        self._model = settings.featherless_model
        # openai.OpenAI holds the key internally for the Authorization header;
        # it is never read back out of this client.
        self._client = openai.OpenAI(
            api_key=settings.featherless_api_key,
            base_url=settings.featherless_base_url,
            timeout=timeout,
        )

    def analyze(self, evidence: dict[str, Any]) -> Investigation:
        messages = build_investigation_prompt(evidence)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=0,
                max_tokens=2048,
            )
        except openai.APITimeoutError as exc:
            raise FeatherlessError("Featherless request timed out") from exc
        except openai.APIConnectionError as exc:
            raise FeatherlessError("Could not connect to Featherless") from exc
        except openai.AuthenticationError as exc:
            raise FeatherlessError("Featherless authentication failed") from exc
        except openai.RateLimitError as exc:
            raise FeatherlessError("Featherless rate limit exceeded") from exc
        except openai.APIStatusError as exc:
            raise FeatherlessError(f"Featherless API error (status {exc.status_code})") from exc
        except openai.APIError as exc:
            raise FeatherlessError("Featherless API error") from exc

        content = response.choices[0].message.content if response.choices else None
        if not content:
            raise FeatherlessError("Featherless returned an empty response")

        payload = self._parse_json(content)
        try:
            investigation = Investigation.model_validate(payload)
        except ValidationError as exc:
            raise FeatherlessError(
                f"Featherless response failed schema validation: {exc}"
            ) from exc

        self._validate_provenance(investigation, evidence)
        return investigation

    @staticmethod
    def _validate_provenance(investigation: Investigation, evidence: dict[str, Any]) -> None:
        # Schema validation only confirms the response is well-formed JSON
        # matching Investigation's shape -- it says nothing about whether
        # the event_ids inside it are real. A hallucinated event_id would
        # otherwise pass through as if it were confirmed evidence. Every
        # event_id the model references must actually appear in the
        # evidence it was given.
        valid_ids = known_event_ids(evidence)
        referenced_ids = {investigation.critical_decision.event_id} | {
            item.event_id for item in investigation.evidence_interpretation
        }
        fabricated = referenced_ids - valid_ids
        if fabricated:
            raise FeatherlessError(
                "Featherless referenced event_id(s) not present in the supplied "
                f"evidence (fabricated or hallucinated): {sorted(fabricated)}"
            )

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        # Models sometimes wrap JSON in a markdown fence despite instructions
        # not to; strip that defensively rather than failing on it.
        cleaned = _JSON_FENCE_RE.sub("", content.strip())
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise FeatherlessError("Featherless response was not valid JSON") from exc

"""Checkpoint 9 -- investigator integration review. These are the gaps
identified by re-inspecting investigator.py against the checkpoint's
checklist that weren't already covered by an existing test; everything
else (framework independence, evidence preservation, correct fallback
behavior, dependency injection) was already proven in earlier checkpoints
and isn't re-tested here to avoid duplication.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from backend.app.core.config import Settings
from backend.app.understand.investigation.investigator import investigate
from tests.test_contracts import make_incident


def make_settings() -> Settings:
    return Settings(
        db_path=":memory:",
        featherless_api_key="test-key",
        featherless_base_url="https://api.featherless.ai/v1",
        featherless_model="test-model",
    )


def test_no_duplicated_featherless_logic_outside_the_client():
    # Static proof: only featherless/client.py may import openai anywhere
    # under app.understand -- if a second call site appeared, that would
    # be exactly the "duplicated Featherless logic" this checkpoint warns
    # against.
    understand_root = pathlib.Path(__file__).resolve().parent.parent / "app" / "understand"
    offenders: list[str] = []
    for path in understand_root.rglob("*.py"):
        if path.name == "client.py" and path.parent.name == "featherless":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "openai" in node.module:
                offenders.append(str(path))
            elif isinstance(node, ast.Import) and any("openai" in a.name for a in node.names):
                offenders.append(str(path))

    assert offenders == []


def test_investigate_only_catches_featherless_error_not_arbitrary_bugs():
    # A real bug in the injected client (anything other than the
    # FeatherlessError contract) must propagate, not be silently absorbed
    # into a "safe-looking" fallback result that hides the actual defect.
    class _BuggyClient:
        def analyze(self, evidence):
            raise TypeError("someone passed the wrong argument type")

    with pytest.raises(TypeError, match="wrong argument type"):
        investigate(make_incident(), settings=make_settings(), client=_BuggyClient())


def test_investigate_signature_is_the_documented_simple_interface():
    # The objective's stated interface is investigate(incident) -- confirm
    # that's still true (incident is the only required argument).
    import inspect

    sig = inspect.signature(investigate)
    required = [
        name
        for name, param in sig.parameters.items()
        if param.default is inspect.Parameter.empty
    ]
    assert required == ["incident"]

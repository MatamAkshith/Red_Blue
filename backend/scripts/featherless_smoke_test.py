#!/usr/bin/env python3
"""Manual integration script -- NOT collected by pytest, NOT part of the
automated test suite. Run it by hand to verify a real Featherless call
works end-to-end:

    cd backend
    ../.venv/bin/python scripts/featherless_smoke_test.py

Requires FEATHERLESS_API_KEY (and, optionally, FEATHERLESS_MODEL) to be
set -- via a local .env (gitignored) or the environment. Exits 1 with a
clear message if they aren't configured, rather than silently no-op'ing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.understand.evidence.extractor import build_prompt_evidence  # noqa: E402
from backend.app.understand.featherless.client import FeatherlessClient, FeatherlessError  # noqa: E402
from tests.test_contracts import make_incident  # noqa: E402


def main() -> int:
    settings = get_settings()

    if not settings.featherless_api_key:
        print("FEATHERLESS_API_KEY is not set -- nothing to test. Set it in .env.")
        return 1
    if not settings.featherless_model:
        print("FEATHERLESS_MODEL is not set -- nothing to test. Set it in .env.")
        return 1

    print(f"Using model: {settings.featherless_model}")
    print(f"Using base URL: {settings.featherless_base_url}")

    evidence = build_prompt_evidence(make_incident())
    client = FeatherlessClient(settings)

    try:
        result = client.analyze(evidence)
    except FeatherlessError as exc:
        print(f"FAILED: {exc}")
        return 1

    print("SUCCESS\n")
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Loaded once at import time so FEATHERLESS_API_KEY etc. from a local .env
# (gitignored, never committed) are available before get_settings() reads
# them. Searches the current directory and its parents, so this works
# whether the backend is run from the repo root or from backend/.
load_dotenv()


@dataclass(frozen=True)
class Settings:
    db_path: str
    featherless_api_key: str | None
    featherless_base_url: str
    featherless_model: str


def get_settings() -> Settings:
    default_db = "/tmp/blackbox.db" if os.environ.get("VERCEL") else "blackbox.db"
    return Settings(
        db_path=os.environ.get("REDBLUE_DB_PATH") or os.environ.get("BLACKBOX_DB_PATH", default_db),
        featherless_api_key=os.environ.get("FEATHERLESS_API_KEY"),
        featherless_base_url=os.environ.get(
            "FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1"
        ),
        featherless_model=os.environ.get(
            "FEATHERLESS_MODEL", "NousResearch/Meta-Llama-3.1-8B-Instruct"
        ),
    )

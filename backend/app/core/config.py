import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str
    featherless_api_key: str | None
    featherless_base_url: str
    featherless_model: str


def get_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("BLACKBOX_DB_PATH", "blackbox.db"),
        featherless_api_key=os.environ.get("FEATHERLESS_API_KEY"),
        featherless_base_url=os.environ.get(
            "FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1"
        ),
        featherless_model=os.environ.get("FEATHERLESS_MODEL", "featherless/default"),
    )

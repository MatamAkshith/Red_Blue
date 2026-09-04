from app.core.config import get_settings


def test_defaults_when_env_unset(monkeypatch):
    monkeypatch.delenv("FEATHERLESS_API_KEY", raising=False)
    monkeypatch.delenv("FEATHERLESS_BASE_URL", raising=False)
    monkeypatch.delenv("FEATHERLESS_MODEL", raising=False)
    monkeypatch.delenv("BLACKBOX_DB_PATH", raising=False)

    settings = get_settings()

    assert settings.featherless_api_key is None
    assert settings.featherless_base_url == "https://api.featherless.ai/v1"
    assert settings.featherless_model == "NousResearch/Meta-Llama-3.1-8B-Instruct"
    assert settings.db_path == "blackbox.db"


def test_reads_from_environment(monkeypatch):
    monkeypatch.setenv("FEATHERLESS_API_KEY", "env-key")
    monkeypatch.setenv("FEATHERLESS_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("FEATHERLESS_MODEL", "some-org/some-model")
    monkeypatch.setenv("BLACKBOX_DB_PATH", "/tmp/custom.db")

    settings = get_settings()

    assert settings.featherless_api_key == "env-key"
    assert settings.featherless_base_url == "https://example.test/v1"
    assert settings.featherless_model == "some-org/some-model"
    assert settings.db_path == "/tmp/custom.db"


def test_settings_is_frozen():
    settings = get_settings()
    try:
        settings.featherless_api_key = "mutated"  # type: ignore[misc]
        assert False, "Settings should be immutable"
    except Exception:
        pass

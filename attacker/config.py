"""Configuration loader for BLACKBOX Synthetic Attack Simulator."""

import os
from pathlib import Path


def _load_env_file() -> None:
    """Load .env file into os.environ if present without overwriting existing environment variables."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).parent / ".env",
    ]
    seen = set()
    for env_path in candidates:
        try:
            resolved = env_path.resolve()
        except Exception:
            resolved = env_path
        if resolved in seen:
            continue
        seen.add(resolved)
        
        if env_path.exists() and env_path.is_file():
            try:
                import dotenv
                dotenv.load_dotenv(env_path, override=False)
            except ImportError:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            key = k.strip()
                            val = v.strip().strip("'\"")
                            if key:
                                os.environ.setdefault(key, val)


_load_env_file()


class AttackerConfig:
    """Attacker configuration settings."""

    ALLOWED_SCHEMES = ("http", "https")
    # Allowed host prefixes for safety validation (prevents arbitrary public internet phishing)
    ALLOWED_HOST_PREFIXES = (
        "127.",
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.",
        "192.168.",
        "localhost",
        "0.0.0.0",
    )

    def __init__(self, host: str | None = None, port: int | None = None, endpoint: str | None = None, timeout: float | None = None):
        self.host = (host if host is not None else os.getenv("TARGET_HOST", "127.0.0.1")).strip()
        
        port_val = port if port is not None else os.getenv("TARGET_PORT", "8000")
        self.port = int(str(port_val).strip())
        
        endpoint_val = endpoint if endpoint is not None else os.getenv("TARGET_ENDPOINT", "/events/run-demo")
        self.endpoint = str(endpoint_val).strip()
        if not self.endpoint.startswith("/"):
            self.endpoint = "/" + self.endpoint
        
        timeout_val = timeout if timeout is not None else os.getenv("TARGET_TIMEOUT", "10.0")
        self.timeout = float(str(timeout_val).strip())

    @property
    def target_url(self) -> str:
        return f"http://{self.host}:{self.port}{self.endpoint}"

    def validate(self) -> None:
        """Validate safety constraints to prevent misuse outside controlled demo environments."""
        if not self.host:
            raise ValueError("TARGET_HOST cannot be empty.")
        
        # Check host safety
        is_safe_host = (
            self.host.endswith(".local") or
            any(self.host.startswith(prefix) for prefix in self.ALLOWED_HOST_PREFIXES)
        )
        if not is_safe_host:
            raise ValueError(
                f"Safety Violation: TARGET_HOST '{self.host}' is not a recognized local or private IP address. "
                "The attacker simulator only operates against controlled demo targets (localhost, 192.168.x.x, 10.x.x.x, *.local)."
            )

        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid TARGET_PORT: {self.port}. Must be between 1 and 65535.")


def get_config() -> AttackerConfig:
    config = AttackerConfig()
    config.validate()
    return config

"""Configuration loader for BLACKBOX Synthetic Attack Simulator."""

import os
from pathlib import Path
from urllib.parse import urlparse


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
    ALLOWED_HOST_SUFFIXES = (
        ".onrender.com",
        "onrender.com",
        ".render.com",
        ".onrender.app",
        ".vercel.app",
    )

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        endpoint: str | None = None,
        timeout: float | None = None,
        scheme: str | None = None,
        target_url: str | None = None,
    ):
        raw_url = target_url or os.getenv("TARGET_URL")
        raw_host = host if host is not None else os.getenv("TARGET_HOST")

        parsed_scheme = scheme or os.getenv("TARGET_SCHEME")
        parsed_host = raw_host
        parsed_port = port if port is not None else os.getenv("TARGET_PORT")
        parsed_endpoint = endpoint if endpoint is not None else os.getenv("TARGET_ENDPOINT")

        # If a full target_url or raw_host starting with http(s):// is provided, parse it
        url_to_parse = raw_url or (raw_host if raw_host and (raw_host.startswith("http://") or raw_host.startswith("https://")) else None)
        if url_to_parse:
            u = urlparse(url_to_parse)
            if u.scheme:
                parsed_scheme = u.scheme
            if u.hostname:
                parsed_host = u.hostname
            if u.port:
                parsed_port = u.port
            elif u.scheme == "https" and parsed_port is None:
                parsed_port = 443
            elif u.scheme == "http" and parsed_port is None:
                parsed_port = 80
            if u.path and u.path != "/":
                parsed_endpoint = u.path

        self.host = (parsed_host if parsed_host else "127.0.0.1").strip()
        
        # Scheme determination
        if parsed_scheme:
            self.scheme = parsed_scheme.strip().lower()
        elif any(self.host.endswith(suf) for suf in self.ALLOWED_HOST_SUFFIXES) or self.host in self.ALLOWED_HOST_SUFFIXES:
            self.scheme = "https"
        else:
            self.scheme = "http"

        # Port determination
        if parsed_port is not None:
            self.port = int(str(parsed_port).strip())
        elif self.scheme == "https":
            self.port = 443
        else:
            self.port = 8000

        # Endpoint determination
        endpoint_val = parsed_endpoint if parsed_endpoint is not None else "/events/run-demo"
        self.endpoint = str(endpoint_val).strip()
        if not self.endpoint.startswith("/"):
            self.endpoint = "/" + self.endpoint

        timeout_val = timeout if timeout is not None else os.getenv("TARGET_TIMEOUT", "10.0")
        self.timeout = float(str(timeout_val).strip())

    @property
    def target_url(self) -> str:
        if self.scheme == "https":
            if self.port == 443:
                return f"https://{self.host}{self.endpoint}"
            return f"https://{self.host}:{self.port}{self.endpoint}"
        else:
            if self.port == 80:
                return f"http://{self.host}{self.endpoint}"
            return f"http://{self.host}:{self.port}{self.endpoint}"

    def validate(self) -> None:
        """Validate safety constraints to prevent misuse outside controlled demo environments."""
        if not self.host:
            raise ValueError("TARGET_HOST cannot be empty.")
        
        # Check host safety
        is_safe_host = (
            self.host.endswith(".local") or
            any(self.host.startswith(prefix) for prefix in self.ALLOWED_HOST_PREFIXES) or
            any(self.host.endswith(suffix) for suffix in self.ALLOWED_HOST_SUFFIXES) or
            self.host in self.ALLOWED_HOST_SUFFIXES
        )
        if not is_safe_host:
            raise ValueError(
                f"Safety Violation: TARGET_HOST '{self.host}' is not a recognized local or private IP address or authorized demo host. "
                "The attacker simulator only operates against controlled demo targets (localhost, 192.168.x.x, 10.x.x.x, *.local, *.onrender.com)."
            )

        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid TARGET_PORT: {self.port}. Must be between 1 and 65535.")


def get_config() -> AttackerConfig:
    config = AttackerConfig()
    config.validate()
    return config


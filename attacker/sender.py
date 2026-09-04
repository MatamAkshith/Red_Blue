"""Sender module for delivering synthetic email payloads to the target machine."""

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from attacker.config import AttackerConfig, get_config


class DeliveryResult:
    def __init__(self, success: bool, status_code: int, response_data: dict[str, Any] | str, error_message: str | None = None):
        self.success = success
        self.status_code = status_code
        self.response_data = response_data
        self.error_message = error_message


def load_payload(payload_name: str) -> dict[str, Any]:
    payloads_dir = Path(__file__).parent / "payloads"
    filepath = payloads_dir / payload_name
    if not filepath.exists():
        raise FileNotFoundError(f"Payload file not found: {filepath}")
    
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Required field validation
    required = ["scenario", "id", "sender", "recipient", "subject", "body"]
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError(f"Payload '{payload_name}' is missing required fields: {missing}")
    
    return data


def send_payload(payload_name: str, config: AttackerConfig | None = None) -> DeliveryResult:
    """Send synthetic payload to configured target machine endpoint via HTTP POST."""
    if config is None:
        config = get_config()
    else:
        config.validate()

    payload = load_payload(payload_name)
    
    # Structure request for target endpoint (POST /events/run-demo)
    request_body = {
        "scenario": payload.get("scenario", "malicious"),
        "async_run": False,
        "email_payload": payload,
    }
    
    json_bytes = json.dumps(request_body).encode("utf-8")
    req = urllib.request.Request(
        config.target_url,
        data=json_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "BLACKBOX-Attacker-Simulator/1.0",
        },
        method="POST",
    )
    
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            status_code = resp.status
            body_bytes = resp.read()
            try:
                res_data = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                res_data = body_bytes.decode("utf-8", errors="replace")
            return DeliveryResult(success=True, status_code=status_code, response_data=res_data)
            
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            res_data = json.loads(body)
        except Exception:
            res_data = body
        return DeliveryResult(success=False, status_code=exc.code, response_data=res_data, error_message=str(exc))
    except urllib.error.URLError as exc:
        return DeliveryResult(
            success=False,
            status_code=0,
            response_data={},
            error_message=f"Connection failed: Could not connect to target machine at {config.target_url}. Reason: {exc.reason}",
        )
    except Exception as exc:
        return DeliveryResult(success=False, status_code=0, response_data={}, error_message=str(exc))

"""Script to execute the synthetic benign email scenario."""

import sys
from pathlib import Path

# Add project/attacker root to sys.path so script can be run directly
attacker_dir = Path(__file__).resolve().parents[1]
if str(attacker_dir.parent) not in sys.path:
    sys.path.insert(0, str(attacker_dir.parent))
if str(attacker_dir) not in sys.path:
    sys.path.insert(0, str(attacker_dir))

from attacker.config import get_config
from attacker.sender import load_payload, send_payload


def main() -> None:
    try:
        config = get_config()
    except Exception as exc:
        print("ATTACKER")
        print("---------")
        print("Scenario: BENIGN")
        print("Status: CONFIGURATION ERROR")
        print(f"Error: {exc}")
        sys.exit(1)

    payload = load_payload("benign_email.json")

    print("ATTACKER")
    print("---------")
    print("Scenario: BENIGN")
    print(f"Target: {config.target_url}")
    print(f"Payload: Synthetic benign email ({payload.get('attachment_ref')})")

    result = send_payload("benign_email.json", config)

    if result.success:
        print("Status: SENT")
        target_status = result.response_data.get("status", "RECEIVED") if isinstance(result.response_data, dict) else "RECEIVED"
        print(f"Target Response Status: {target_status}")
    else:
        print("Status: FAILED")
        print(f"Error: {result.error_message}")
        sys.exit(1)


if __name__ == "__main__":
    main()

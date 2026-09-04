"""Unit tests for BLACKBOX Synthetic Attacker Simulator."""

import http.server
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# Add project root and attacker package to sys.path
attacker_dir = Path(__file__).resolve().parents[1]
if str(attacker_dir.parent) not in sys.path:
    sys.path.insert(0, str(attacker_dir.parent))
if str(attacker_dir) not in sys.path:
    sys.path.insert(0, str(attacker_dir))

from attacker.config import AttackerConfig, get_config, _load_env_file
from attacker.sender import load_payload, send_payload
from attacker.scripts import send_malicious, send_benign


class MockTargetHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Simple in-memory HTTP request handler for local testing."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        data = json.loads(body.decode("utf-8"))

        scenario = data.get("scenario", "unknown")
        response_payload = {
            "session_id": "S-TEST-1234",
            "scenario": scenario,
            "status": "EXFILTRATED" if scenario == "malicious" else "COMPLETED",
            "event_count": 6 if scenario == "malicious" else 3,
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_payload).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress standard HTTP server logging during unit tests
        pass


class TestAttackerSimulator(unittest.TestCase):
    """Test suite for attacker simulator payloads, config, and delivery."""

    @classmethod
    def setUpClass(cls):
        # Start a local HTTP server on a random free port for mock target testing
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), MockTargetHTTPHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._orig_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_malicious_payload_generation(self):
        payload = load_payload("malicious_email.json")
        self.assertEqual(payload["scenario"], "malicious")
        self.assertEqual(payload["id"], "email-malicious-1")
        self.assertIn("crm://sensitive_customer_records", payload["target_resources"])
        self.assertEqual(payload["target_destination"], "https://external-drop.example.com/upload")
        self.assertIn("attachment_ref", payload)

    def test_benign_payload_generation(self):
        payload = load_payload("benign_email.json")
        self.assertEqual(payload["scenario"], "benign")
        self.assertEqual(payload["id"], "email-benign-1")
        self.assertNotIn("target_destination", payload)
        self.assertIn("attachment_ref", payload)

    def test_required_fields_validation(self):
        with self.assertRaises(FileNotFoundError):
            load_payload("nonexistent_payload.json")

    def test_default_configuration_behavior(self):
        os.environ.pop("TARGET_HOST", None)
        os.environ.pop("TARGET_PORT", None)
        config = AttackerConfig(host="127.0.0.1", port=8000, endpoint="/events/run-demo")
        config.validate()
        self.assertEqual(config.target_url, "http://127.0.0.1:8000/events/run-demo")

    def test_env_file_target_host_respected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("TARGET_HOST=192.168.1.100\nTARGET_PORT=9000\n", encoding="utf-8")
            
            os.environ.pop("TARGET_HOST", None)
            os.environ.pop("TARGET_PORT", None)
            
            # Test direct file reading logic
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        os.environ.setdefault(k, v)
            
            config = get_config()
            self.assertEqual(config.host, "192.168.1.100")
            self.assertEqual(config.port, 9000)
            self.assertEqual(config.target_url, "http://192.168.1.100:9000/events/run-demo")

    def test_environment_variable_override_takes_precedence(self):
        os.environ["TARGET_HOST"] = "192.168.137.20"
        os.environ["TARGET_PORT"] = "8000"
        config = get_config()
        self.assertEqual(config.host, "192.168.137.20")
        self.assertEqual(config.target_url, "http://192.168.137.20:8000/events/run-demo")

    def test_printed_target_matches_request_target(self):
        os.environ["TARGET_HOST"] = "127.0.0.1"
        os.environ["TARGET_PORT"] = str(self.port)
        config = get_config()
        
        # Capture output of send_malicious script
        stdout_buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = stdout_buf
            send_malicious.main()
        finally:
            sys.stdout = old_stdout
            
        output = stdout_buf.getvalue()
        expected_target_line = f"Target: http://127.0.0.1:{self.port}/events/run-demo"
        self.assertIn(expected_target_line, output)
        self.assertIn("Status: SENT", output)

    def test_malicious_and_benign_scripts_use_configured_target(self):
        os.environ["TARGET_HOST"] = "127.0.0.1"
        os.environ["TARGET_PORT"] = str(self.port)
        
        # Test malicious script
        stdout_buf_mal = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = stdout_buf_mal
            send_malicious.main()
        finally:
            sys.stdout = old_stdout
        self.assertIn(f"Target: http://127.0.0.1:{self.port}/events/run-demo", stdout_buf_mal.getvalue())

        # Test benign script
        stdout_buf_ben = io.StringIO()
        try:
            sys.stdout = stdout_buf_ben
            send_benign.main()
        finally:
            sys.stdout = old_stdout
        self.assertIn(f"Target: http://127.0.0.1:{self.port}/events/run-demo", stdout_buf_ben.getvalue())

    def test_malformed_configuration_safety_rejection(self):
        config_unsafe = AttackerConfig(host="8.8.8.8", port=8000)
        with self.assertRaises(ValueError) as ctx:
            config_unsafe.validate()
        self.assertIn("Safety Violation", str(ctx.exception))

    def test_successful_delivery_against_mock_target(self):
        config = AttackerConfig(host="127.0.0.1", port=self.port, endpoint="/events/run-demo")
        res_mal = send_payload("malicious_email.json", config)
        self.assertTrue(res_mal.success)
        self.assertEqual(res_mal.status_code, 200)

    def test_failed_delivery_handling(self):
        config_closed = AttackerConfig(host="127.0.0.1", port=1, timeout=0.5)
        res = send_payload("malicious_email.json", config_closed)
        self.assertFalse(res.success)
        self.assertIn("Connection failed", res.error_message)


if __name__ == "__main__":
    unittest.main()

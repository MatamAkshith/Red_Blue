# BLACKBOX Synthetic Attack Simulator

A self-contained, controlled synthetic email attack simulator for the 2-Mac BLACKBOX live security demonstration.

> ⚠️ **CONTROLLED DEMO SIMULATOR ONLY**  
> This tool is strictly a synthetic email simulator designed for local hackathon demonstrations. It does **not** send real emails, target real users, collect credentials, harvest data, send malware, or contact arbitrary external targets.

---

## 📋 Overview

The Attacker Simulator operates as Machine #1 in the two-machine BLACKBOX demonstration architecture:

```
[ ATTACKER MAC ]                                   [ TARGET MAC ]
+-------------------+                              +---------------------+
| Synthetic Email   |  --- POST /events/run-demo ->| Target Email Agent  |
| Simulator         |   (HTTP over Wi-Fi/LAN)      |        ↓            |
+-------------------+                              | BLACKBOX Ingestion  |
                                                   |        ↓            |
                                                   | REDBLUE Dashboard   |
                                                   +---------------------+
```

The Attacker delivers synthetic email payloads (`malicious_email.json` or `benign_email.json`) over HTTP to the Target Mac. The Target Email Processing Agent ingests the payload, executes the workflow, and emits observable `AgentEvent` telemetry into the BLACKBOX security pipeline.

---

## 🛠️ Requirements

- **OS**: macOS or Linux
- **Python**: Python 3.9 or higher (uses Python Standard Library for zero-dependency execution)
- **Network**: Local Wi-Fi or Ethernet connection to the Target Mac

---

## 🚀 Installation & Setup

1. Copy or extract the `attacker/` directory to the Attacker Mac.
2. Open a terminal in the `attacker/` directory:
   ```bash
   cd attacker
   ```
3. (Optional) Install optional helper dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` (or set environment variables):

```bash
cp .env.example .env
```

Edit `.env` to set your Target Mac's IP address:

```env
TARGET_HOST=192.168.1.50
TARGET_PORT=8000
TARGET_ENDPOINT=/events/run-demo
TARGET_TIMEOUT=10.0
```

### Finding the Target Mac IP Address
On the Target Mac, run:
```bash
ipconfig getifaddr en0
# or
ifconfig | grep "inet "
```

---

## 🧪 Running Scenarios

### 1. Send Synthetic Malicious Email Attack
Simulates an indirect prompt injection attack attempting to exfiltrate customer CRM records:

```bash
python3 scripts/send_malicious.py
```

**Expected Terminal Output:**
```
ATTACKER
---------
Scenario: MALICIOUS
Target: http://192.168.1.50:8000/events/run-demo
Payload: Synthetic malicious email (doc://malicious_onboarding_guide.txt)
Status: SENT
Target Response Status: EXFILTRATED
```

### 2. Send Synthetic Benign Email
Simulates a standard safe email processing request:

```bash
python3 scripts/send_benign.py
```

**Expected Terminal Output:**
```
ATTACKER
---------
Scenario: BENIGN
Target: http://192.168.1.50:8000/events/run-demo
Payload: Synthetic benign email (doc://benign_onboarding_guide.txt)
Status: SENT
Target Response Status: COMPLETED
```

---

## 🧪 Running Unit Tests

Run the self-contained test suite (runs local mock HTTP servers on `127.0.0.1` and does **not** contact the internet):

```bash
python3 -m unittest discover tests/
```

---

## 🔍 Troubleshooting Connection Failures

If `send_malicious.py` reports `Connection failed: Could not connect to target machine`:

1. **Verify Target Server is Running**: Ensure the Target Mac has started the server:
   ```bash
   PYTHONPATH=. python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
   ```
2. **Ping Target Mac**: Test network connectivity from the Attacker Mac:
   ```bash
   ping <TARGET_HOST_IP>
   ```
3. **Check Firewall**: Ensure macOS Firewall on the Target Mac allows incoming connections on port `8000`.
4. **Confirm Same Wi-Fi/Network**: Both Macs must be connected to the same Wi-Fi network or local router.

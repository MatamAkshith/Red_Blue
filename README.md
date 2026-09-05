# REDBLUE

### Adaptive Security & Forensic Intelligence for AI Agents & AI Automation

**HackWave 3.0**

> **Observe. Detect. Explain. Simulate. Defend. Verify.**

REDBLUE is an adaptive security and forensic intelligence platform designed to protect AI agents and AI-powered automation. Rather than securing the underlying model, REDBLUE secures the **behavior of the agent**: it observes activity, reconstructs execution behavior, detects dangerous behavior deterministically, calculates impact and blast radius, explains incidents using an LLM, determines the smallest effective intervention, enforces the defense at the target agent's action boundary, and re-attacks the target to verify that the defense actually works.

> **Deterministic systems establish security truth. LLMs explain that truth. An LLM is never the final authority on whether an event happened, whether a resource is reachable, blast radius, authorization, policy enforcement, or whether a defense worked.**

---

## 1. Problem

Modern AI agents can consume untrusted content, retrieve sensitive information, invoke privileged tools, make autonomous decisions, access internal resources, communicate externally, and execute multi-step workflows.

Traditional security monitoring often treats these actions as isolated logs. An attack against an AI agent, however, is usually behavioral and multi-step:

```text
Untrusted Email
      ↓
Malicious Document
      ↓
Indirect Prompt Injection
      ↓
Agent Changes Intended Plan
      ↓
CRM Export Tool
      ↓
Sensitive Customer Records
      ↓
External Destination
```

REDBLUE reconstructs this entire chain instead of treating each event independently.

---

## 2. Solution

```text
Real AI Agent
     ↓
REDBLUE Enforcement Guard
     ↓
Event Collector
     ↓
Universal AgentEvent
     ↓
Execution Graph
     ├── Detection
     ├── AEGIS Impact Analysis
     └── Evidence Extraction
             ↓
          Incident
             ↓
      Understand Layer
             ↓
        Featherless
             ↓
       What-If Simulation
             ↓
         Intervention
             ↓
       Apply Defense
             ↓
    REDBLUE Enforcement
             ↓
          CHIMERA
          Re-Attack
             ↓
        Verification
             ↓
      Adaptive Memory
```

---

## 3. Core Security Principle

REDBLUE strictly separates **security truth** from **AI explanation**.

### Deterministic systems establish security truth

The deterministic engine decides:

- what events occurred,
- how events are related,
- what the execution path was,
- whether a security rule was violated,
- which resources were reached,
- what the blast radius is,
- whether an intervention can sever the attack path,
- what intervention is required,
- whether the re-attack was blocked.

### LLMs explain that truth

Featherless is used for:

- root-cause explanation,
- incident investigation,
- narrative generation,
- critical decision explanation,
- evidence-backed reasoning.

The LLM cannot overwrite facts established by REDBLUE.

---

## 4. End-to-End Security Loop

```text
OBSERVE
   ↓
DETECT
   ↓
RECONSTRUCT
   ↓
ASSESS IMPACT
   ↓
UNDERSTAND
   ↓
SIMULATE
   ↓
INTERVENE
   ↓
ENFORCE
   ↓
RE-ATTACK
   ↓
VERIFY
   ↓
REMEMBER
```

---

## 5. Universal AgentEvent

All agent activity is represented through a canonical `AgentEvent` schema.

Security-relevant fields include:

- event ID
- session ID
- agent ID
- event type
- source
- timestamp
- resource
- trust level
- parent event
- tool/action metadata
- execution context

This creates a common telemetry model for different AI-agent workflows.

---

## 6. Event Collection & Storage

REDBLUE uses an append-oriented SQLite event store.

```text
Agent
  ↓
REDBLUE Observer / Guard
  ↓
Event Collector
  ↓
EventStore
  ↓
SQLite
```

Historical telemetry is treated as immutable security evidence.

Live attacks create dynamic sessions such as:

```text
S-LIVE-e7ba3c
S-LIVE-bb81af
S-LIVE-xxxxxx
```

The dashboard can automatically discover these sessions.

---

## 7. Execution Graph

The Execution Graph is the central computational object.

Instead of viewing telemetry as:

```text
E1 → E2 → E3 → E4 → E5 → E6
```

REDBLUE reconstructs behavioral relationships:

```text
INPUT
  ↓
RETRIEVAL
  ↓
DECISION
  ↓
TOOL_CALL
  ↓
TOOL_RESULT
  ↓
ACTION
```

Relationships are represented through `parent_event_id`.

The graph enables:

- ancestry analysis,
- descendant traversal,
- attack-path reconstruction,
- causal lineage,
- blast-radius calculation,
- deterministic What-If simulation,
- intervention analysis,
- defense verification.

---

## 8. Deterministic Detection Engine

REDBLUE currently implements deterministic detection for:

### Indirect Prompt Injection

Detects when untrusted content influences agent behavior or causes an unauthorized plan/action.

### Tool Abuse / Privilege Violation

Detects unauthorized or suspicious use of privileged capabilities and sensitive tools.

### Data Exfiltration

Detects sensitive data reaching external destinations.

Example:

```text
Untrusted Input
      ↓
Injected Instruction
      ↓
CRM Export
      ↓
Sensitive Customer Data
      ↓
External Destination
```

Detection does not depend on an LLM.

---

## 9. AEGIS — Impact & Blast Radius

**AEGIS** is REDBLUE's deterministic impact-analysis capability.

It identifies:

- affected resources,
- sensitive resources,
- reachable descendants,
- external destinations,
- trust-boundary crossings,
- affected capabilities,
- potential blast radius.

Example:

```text
Compromised Agent
       │
       ├── CRM Customer Records
       ├── Export Capability
       └── External Destination
                ↓
        external-drop.example.com
```

AEGIS answers:

> **"If this execution path continues, what can actually be affected?"**

---

## 10. Evidence Extraction

The evidence extraction layer converts deterministic security findings into an LLM-ready evidence package.

The package contains facts already established by REDBLUE.

The LLM is not asked to rediscover:

- attack paths,
- permissions,
- blast radius,
- sensitive resources,
- event history.

This keeps generated explanations grounded in security evidence.

---

## 11. Understand Layer & Featherless

The Understand layer uses **Featherless AI** through an OpenAI-compatible interface.

It provides:

- root cause,
- incident explanation,
- critical decision analysis,
- evidence-backed narrative,
- investigation summary.

LLM output is schema validated.

If Featherless is unavailable, REDBLUE falls back to deterministic explanations.

```text
Featherless Available
        ↓
LLM Investigation
        ↓
Structured Explanation

Featherless Unavailable
        ↓
Deterministic Fallback
        ↓
Structured Explanation
```

Security functionality does not depend on the LLM being online.

---

## 12. P1 → P2 Security Contract

REDBLUE uses a frozen `IncidentAnalysis` contract between deterministic security analysis and the Understand layer.

```text
P1 — Security Truth
       ↓
IncidentAnalysis
       ↓
P2 — Explanation
```

P2 cannot overwrite P1 security facts.

---

## 13. What-If Simulation

REDBLUE performs deterministic counterfactual security simulation.

Instead of asking an LLM what might happen, REDBLUE modifies the execution graph and recomputes the security state.

Example:

```text
Original:

CRM Data
   ↓
External Destination
   ↓
EXFILTRATION
```

After simulated intervention:

```text
BLOCK_EXTERNAL_DESTINATION
          ↓
CRM Data
   ↓
   X
External Destination
```

REDBLUE then reruns detection and impact analysis to determine whether the attack path was actually severed.

---

## 14. Minimum-Effective Intervention

REDBLUE searches for the **smallest effective defense** instead of automatically choosing the most disruptive response.

| Intervention | Cost |
|---|---:|
| `BLOCK_EXTERNAL_DESTINATION` | 1 |
| `BLOCK_RESOURCE` | 2 |
| `BLOCK_TOOL` | 3 |
| `KILL_AGENT` | 10 |

If blocking a single destination prevents exfiltration, REDBLUE prefers that intervention over blocking an entire tool or killing the agent.

---

## 15. REDBLUE Enforcement Guard

Defense is not merely represented in the dashboard.

REDBLUE includes an enforcement guard at the controlled target agent's external action boundary:

```text
AI Agent
   ↓
REDBLUE Enforcement Guard
   ↓
Policy Evaluation
   ├── ALLOW → Execute
   └── BLOCK → Prevent Action
```

For example:

```text
BLOCK_EXTERNAL_DESTINATION
https://external-drop.example.com/upload
```

prevents the controlled external action **before transmission**.

Historical telemetry remains immutable.

---

## 16. CHIMERA — Controlled Re-Attack

CHIMERA is REDBLUE's controlled attack replay and verification capability.

```text
Attack Before Defense
        ↓
      SUCCESS
        ↓
Apply Defense
        ↓
CHIMERA Re-Attack
        ↓
      BLOCKED
        ↓
Defense Verified
```

Example:

```text
Attack Before: SUCCESS
Attack After:  BLOCKED
Defense:       BLOCK_EXTERNAL_DESTINATION
Verified:      TRUE
```

A defense is not considered successful merely because it was applied; it must survive the controlled re-attack.

---

## 17. Adaptive Memory

REDBLUE stores structural failure patterns in adaptive memory.

Patterns can include:

- detector types,
- sensitive resources,
- external reachability,
- recurring attack structures.

The current memory layer supports passive pattern recall and provides a foundation for future active runtime protection.

---

## 18. Controlled Target Agent

REDBLUE includes a controlled target agent representing an AI-powered workflow.

### Benign workflow

```text
Normal Input
   ↓
Normal Retrieval
   ↓
Normal Decision
   ↓
Authorized Tool
   ↓
Completed
```

### Malicious workflow

```text
Malicious Input
      ↓
Untrusted Document
      ↓
Indirect Prompt Injection
      ↓
Unauthorized Decision
      ↓
CRM Export
      ↓
Sensitive Data
      ↓
External Destination
```

The target provides a controlled environment for demonstrating detection, enforcement, and verification.

---

## 19. Attacker → Target Architecture

REDBLUE supports a two-machine demonstration.

```text
┌─────────────────────────────┐
│       ATTACKER MAC          │
│                             │
│  Malicious / Benign Payload │
│           │                 │
│           ▼                 │
│     attacker/scripts/       │
└─────────────┬───────────────┘
              │ HTTP
              ▼
┌─────────────────────────────┐
│        TARGET MAC           │
│                             │
│     FastAPI Backend         │
│            │                │
│            ▼                │
│      Target AI Agent        │
│            │                │
│            ▼                │
│   REDBLUE Enforcement Guard │
│            │                │
│            ▼                │
│       Event Collector       │
│            │                │
│            ▼                │
│      Security Pipeline      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│       REDBLUE UI            │
│                             │
│ Detection                   │
│ Execution Graph             │
│ AEGIS                       │
│ What-If                     │
│ Intervention                │
│ CHIMERA                     │
│ Verification                │
└─────────────────────────────┘
```

The attacker package is self-contained and can be distributed separately from the main development environment.

---

## 20. Live Session Discovery

External attacks create dynamic sessions:

```text
S-LIVE-xxxxxx
```

The REDBLUE dashboard discovers live sessions through:

```http
GET /events/sessions
```

The frontend then:

1. discovers the latest live session,
2. retrieves its events,
3. analyzes the incident,
4. updates the active incident,
5. updates the execution graph,
6. updates AEGIS,
7. updates What-If,
8. updates Intervention,
9. updates CHIMERA / Verification state.

Externally generated attacks do not require clicking the dashboard's demo button.

The Overview and Incidents views use the current live incident state rather than a hardcoded incident ID.

---

## 21. REDBLUE Dashboard

The REDBLUE dashboard is the operational Security Operations Center interface.

It provides:

- Overview
- Incidents
- Execution
- Attack Path
- AEGIS
- What-If
- Intervention
- CHIMERA
- Verification

The interface is designed as an enterprise SOC-style dashboard with live monitoring.

---

## 22. Example Attack

A malicious controlled payload produces an execution chain similar to:

```text
E1 INPUT
External Email
        ↓
E2 RETRIEVAL
Untrusted Malicious Document
        ↓
E3 DECISION
Injected instruction influences agent plan
        ↓
E4 TOOL_CALL
CRM sensitive customer records export
        ↓
E5 TOOL_RESULT
PII returned
        ↓
E6 ACTION
External destination
```

REDBLUE detects:

```text
INDIRECT_PROMPT_INJECTION
PRIVILEGE_VIOLATION
DATA_EXFILTRATION
```

AEGIS identifies:

```text
Sensitive Resource:
CRM Customer Records

External Destination:
external-drop.example.com

Affected Capabilities:
Export / Plan / Read
```

---

## 23. Example Defense

Baseline:

```text
Attack Before: SUCCESS
```

What-If:

```text
Candidate:
BLOCK_EXTERNAL_DESTINATION

Cost:
1

Result:
Exfiltration path severed
```

Intervention:

```text
BLOCK_EXTERNAL_DESTINATION
```

Enforcement:

```text
External action prevented before transmission
```

CHIMERA:

```text
Original Attack:
SUCCESS

Re-Attack:
BLOCKED
```

Final:

```text
DEFENSE VERIFIED
```

---

## 24. Technology Stack

### Backend

| Technology | Purpose |
|---|---|
| **Python** | Core backend and security logic |
| **FastAPI** | REST API and live event ingestion |
| **Pydantic** | Event and contract validation |
| **SQLite** | Event storage |
| **NetworkX** | Execution graph construction and traversal |
| **Uvicorn** | ASGI application server |
| **pytest** | Automated backend testing |

### AI / Understand Layer

| Technology | Purpose |
|---|---|
| **Featherless AI** | LLM inference |
| **OpenAI-compatible API** | Model communication |
| **Configurable LLM model** | Investigation / root cause / narrative |
| **Pydantic schemas** | LLM output validation |
| **Deterministic fallback** | Operation when LLM is unavailable |

### Frontend

| Technology | Purpose |
|---|---|
| **React** | Dashboard UI |
| **TypeScript** | Type-safe frontend development |
| **Vite** | Frontend build and development |
| **Tailwind CSS** | UI styling |
| **REST API** | Backend communication |

### Security / Intelligence

| Component | Purpose |
|---|---|
| **Execution Graph** | Behavioral reconstruction |
| **Detection Engine** | Deterministic threat detection |
| **AEGIS** | Impact / blast-radius analysis |
| **What-If** | Counterfactual security simulation |
| **Intervention Engine** | Minimum-effective defense |
| **REDBLUE Enforcement Guard** | Controlled runtime policy enforcement |
| **CHIMERA** | Controlled re-attack and verification |
| **Adaptive Memory** | Failure-pattern storage and recall |

---

## 25. Project Structure

```text
REDBLUE/
│
├── backend/
│   ├── app/
│   │   ├── aegis/
│   │   ├── api/
│   │   ├── chimera/
│   │   ├── contracts/
│   │   ├── core/
│   │   ├── detection/
│   │   ├── events/
│   │   ├── graph/
│   │   ├── intervention/
│   │   ├── memory/
│   │   ├── scenarios/
│   │   ├── selfprotect/
│   │   ├── understand/
│   │   ├── whatif/
│   │   └── orchestrator.py
│   │
│   ├── tests/
│   └── scripts/
│
├── agent/
│   └── Controlled target AI agent
│
├── attacker/
│   ├── payloads/
│   │   ├── malicious_email.json
│   │   └── benign_email.json
│   ├── scripts/
│   │   ├── send_malicious.py
│   │   └── send_benign.py
│   ├── tests/
│   ├── sender.py
│   ├── config.py
│   ├── requirements.txt
│   └── README.md
│
├── sdk/
│   └── observer.py
│
├── frontend/
│   └── src/
│
├── contracts/
│   └── incident_analysis.json
│
├── requirements.txt
└── README.md
```

---

## 26. API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check |
| `POST /events` | Event ingestion |
| `GET /events?session_id=<SESSION_ID>` | Retrieve session events |
| `GET /events/sessions` | Discover live sessions |
| `POST /events/run-demo` | Run controlled target scenario |
| `POST /investigate` | Run Understand / Featherless investigation |
| `POST /incidents/analyze` | Analyze incident |
| `GET /incidents/demo-scenario` | Retrieve demo scenario |
| `POST /incidents/{incident_id}/simulate` | Run What-If simulation |
| `POST /incidents/{incident_id}/defend` | Apply defense |

---

## 27. Running REDBLUE

### Backend

Create the environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend:

```bash
PYTHONPATH=. python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Expected:

```json
{
  "status": "ok"
}
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 28. Environment Configuration

Create `.env` from the example:

```bash
cp .env.example .env
```

| Variable | Purpose | Default |
|---|---|---|
| `BLACKBOX_DB_PATH` | SQLite event database | `blackbox.db` |
| `FEATHERLESS_API_KEY` | Featherless authentication | none |
| `FEATHERLESS_BASE_URL` | Featherless API endpoint | `https://api.featherless.ai/v1` |
| `FEATHERLESS_MODEL` | Investigation model | `NousResearch/Meta-Llama-3.1-8B-Instruct` |

> `BLACKBOX_DB_PATH` is retained as the existing environment variable name for compatibility with the current implementation.

`.env` is gitignored and secrets are never hardcoded.

---

## 29. Attacker Package

The attacker component is designed as a separate portable package.

### Malicious scenario

```bash
TARGET_HOST=<TARGET_MAC_IP> python3 scripts/send_malicious.py
```

Expected:

```text
Status: SENT
Target Response Status: EXFILTRATED
```

### Benign scenario

```bash
TARGET_HOST=<TARGET_MAC_IP> python3 scripts/send_benign.py
```

Expected:

```text
Status: SENT
Target Response Status: COMPLETED
```

The attacker package is intended for the controlled demonstration target.

---

## 30. Two-Machine Demonstration

### Target Mac

Start the backend:

```bash
PYTHONPATH=. python -m uvicorn backend.app.main:app   --host 0.0.0.0   --port 8000
```

Find the target LAN IP:

```bash
ifconfig | grep "inet "
```

### Attacker Mac

From the attacker package:

```bash
TARGET_HOST=<TARGET_MAC_IP> python3 scripts/send_malicious.py
```

The target receives the attack, creates a live session, processes the agent events, and the REDBLUE dashboard automatically discovers and displays the resulting incident.

Benign testing:

```bash
TARGET_HOST=<TARGET_MAC_IP> python3 scripts/send_benign.py
```

---

## 31. Testing

Run backend tests:

```bash
PYTHONPATH=. ./venv/bin/pytest backend/tests/
```

Verified result:

```text
335 passed
0 failed
```

Run attacker tests:

```bash
python3 -m unittest discover attacker/tests/
```

Verified result:

```text
11 passed
0 failed
```

Build the frontend:

```bash
cd frontend
npm run build
```

Verified result:

```text
Vite build passed
0 errors
```

---

## 32. Complete Live Demonstration Flow

```text
1. Start REDBLUE backend
          ↓
2. Start REDBLUE dashboard
          ↓
3. Start controlled target agent
          ↓
4. Launch malicious payload
   from Attacker Mac
          ↓
5. REDBLUE receives live telemetry
          ↓
6. Execution Graph reconstructs behavior
          ↓
7. Detection Engine identifies violations
          ↓
8. AEGIS calculates blast radius
          ↓
9. Featherless explains root cause
          ↓
10. What-If simulates defenses
          ↓
11. Intervention selects minimum effective defense
          ↓
12. REDBLUE Enforcement Guard applies policy
          ↓
13. CHIMERA re-attacks the target
          ↓
14. Attack is blocked
          ↓
15. REDBLUE marks defense VERIFIED
          ↓
16. Adaptive Memory stores the structural failure pattern
```

---

## 33. Security Principles

### Deterministic Security Truth
Security decisions do not depend on LLM interpretation.

### Evidence First
Generated explanations are grounded in deterministic evidence.

### Immutable Historical Telemetry
Defenses do not rewrite historical events.

### Minimum Effective Defense
REDBLUE prefers the least disruptive intervention that actually stops the attack.

### Defense Verification
A defense is not considered successful merely because it was applied; CHIMERA must demonstrate that the attack is blocked.

### Graceful LLM Failure
If Featherless is unavailable, deterministic investigation continues.

### No Hardcoded Secrets
Credentials are loaded through environment configuration.

### Controlled Demonstration Environment
The attacker and target workflows are designed for controlled testing and demonstration.

---

## 34. Current Implementation Status

| Component | Status |
|---|---|
| Universal AgentEvent | ✅ Complete |
| Event ingestion | ✅ Complete |
| Event storage | ✅ Complete |
| Live session discovery | ✅ Complete |
| Execution Graph | ✅ Complete |
| Deterministic Detection | ✅ Complete |
| Indirect Prompt Injection Detection | ✅ Complete |
| Privilege Violation Detection | ✅ Complete |
| Data Exfiltration Detection | ✅ Complete |
| AEGIS Impact Analysis | ✅ Complete |
| P1 → P2 Contract | ✅ Complete |
| Evidence Extraction | ✅ Complete |
| Featherless Integration | ✅ Complete |
| Investigation Pipeline | ✅ Complete |
| Deterministic LLM Fallback | ✅ Complete |
| What-If Simulation | ✅ Complete |
| Minimum-Effective Intervention | ✅ Complete |
| REDBLUE Enforcement Guard | ✅ Complete |
| CHIMERA Re-Attack | ✅ Complete |
| Defense Verification | ✅ Complete |
| Adaptive Memory | ✅ Implemented |
| Controlled Target Agent | ✅ Implemented |
| Attacker Package | ✅ Implemented |
| Two-Machine Communication | ✅ Verified |
| Live REDBLUE Data Wiring | ✅ Implemented |
| Dynamic Incident State | ✅ Implemented |
| REDBLUE Dashboard | ✅ Implemented |
| Self-Protection / Safe Mode | 🚧 Future extension |
| Generic REDBLUE SDK | 🚧 Future extension |

---

## 35. Design Philosophy

```text
                 SECURITY TRUTH
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
   Detection         AEGIS          Execution Graph
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                  INCIDENT
                       │
                       ▼
                 UNDERSTAND
                       │
                       ▼
                  Featherless
                       │
                  explanation
                       │
                       ▼
                  WHAT-IF
                       │
                       ▼
                INTERVENTION
                       │
                       ▼
                 ENFORCEMENT
                       │
                       ▼
                   CHIMERA
                       │
                       ▼
                 VERIFICATION
                       │
                       ▼
                ADAPTIVE MEMORY
```

**The LLM explains.**

**The deterministic security engine decides.**

**The controlled re-attack proves whether the defense works.**

---

## 36. Why REDBLUE Is Different

Traditional monitoring often answers:

> **"What happened?"**

REDBLUE aims to answer the complete security loop:

> **What happened?**

> **How did the agent get there?**

> **What can the compromised path reach?**

> **Why did the agent make the critical decision?**

> **What is the smallest effective defense?**

> **Will that defense actually stop the attack?**

> **Can we prove it by attacking again?**

This turns agent security from passive observation into **evidence-driven adaptive defense**.

---

## 37. Future Extensions

Potential future extensions include:

- broader agent framework adapters,
- production-grade REDBLUE SDK instrumentation,
- active adaptive-memory enforcement,
- Safe Mode / self-protection,
- additional behavioral detectors,
- policy-based authorization,
- multi-agent attack-path analysis,
- persistent organizational threat intelligence,
- automated incident response,
- richer runtime policy controls.

---

## 38. Render Deployment Guide

REDBLUE is fully deployment-ready for production hosting on [Render](https://render.com).

### Deployment Architecture

```text
Render Static Site (Frontend React/Vite)
             ↓ HTTPS API requests
Render Web Service (Backend FastAPI)
             ↓ Execution Graph / Telemetry
REDBLUE Security & Forensic Engine
```

---

### 1. Automated Blueprint Deployment (`render.yaml`)

REDBLUE includes a root-level `render.yaml` infrastructure-as-code configuration file.

1. Connect your Git repository to Render.
2. Select **Blueprints** from the Render Dashboard.
3. Render automatically detects `render.yaml` and provisions both the Backend Web Service and Frontend Static Site.

---

### 2. Backend Deployment Settings (Render Web Service)

| Setting | Value |
|---|---|
| **Service Type** | Web Service |
| **Environment** | Python |
| **Root Directory** | `.` (repository root) |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT` |

#### Environment Variables (Backend)

| Variable | Description | Example / Recommended Value |
|---|---|---|
| `PYTHONPATH` | Python path | `.` |
| `PORT` | Render port (automatically set by Render) | `$PORT` |
| `HOST` | Bind address | `0.0.0.0` |
| `FRONTEND_URL` | Allowed CORS origin URL(s) | `https://redblue-frontend.onrender.com` |
| `REDBLUE_DB_PATH` | Event store SQLite path | `blackbox.db` |
| `FEATHERLESS_API_KEY` | Featherless API key (Optional) | `featherless_sec_...` |
| `FEATHERLESS_BASE_URL` | Featherless API base URL | `https://api.featherless.ai/v1` |

> **Note on Storage Persistence**: On Render's standard free tier, local filesystem storage (`blackbox.db`) is ephemeral and resets across instance restarts. To preserve events across restarts in production, attach a **Render Persistent Disk** or configure an external database volume.

---

### 3. Frontend Deployment Settings (Render Static Site)

| Setting | Value |
|---|---|
| **Service Type** | Static Site |
| **Build Command** | `cd frontend && npm install && npm run build` |
| **Publish Directory** | `./frontend/dist` |

#### Environment Variables (Frontend)

| Variable | Description | Value |
|---|---|---|
| `VITE_API_URL` | Deployed Backend Web Service URL | `https://redblue-backend.onrender.com` |

---

### 4. Attacker Package Remote Target Configuration

The synthetic attacker package can run locally or from a secondary machine while targeting the deployed Render backend over HTTPS.

#### Configuration (`attacker/.env` or environment variables)

```bash
TARGET_HOST=redblue-backend.onrender.com
TARGET_PORT=443
TARGET_SCHEME=https
TARGET_ENDPOINT=/events/run-demo
```

Or pass a single unified target URL:

```bash
TARGET_URL=https://redblue-backend.onrender.com/events/run-demo
```

#### Running Remote Scenarios

Malicious attack scenario against Render backend:
```bash
python3 scripts/send_malicious.py
```

Benign scenario against Render backend:
```bash
python3 scripts/send_benign.py
```

---

## 39. Vercel Deployment Guide

REDBLUE supports unified full-stack monorepo deployment on [Vercel](https://vercel.com) — hosting both the React/Vite frontend and FastAPI backend.

### Deployment Architecture

```text
Vercel Monorepo
 ├── frontend/  ──> Vercel Static Build (React + Vite)
 └── api/       ──> Vercel Python Function (`backend.app.main:app`)
```

---

### 1. Automatic Deployment (`vercel.json`)

REDBLUE includes a root-level [`vercel.json`](file:///Users/ashu/Documents/VMEG/Hackathons/SNIST/Red_Blue/vercel.json) configuration file.

1. Connect your Git repository to Vercel.
2. Import the project using repository root (`/`).
3. Vercel automatically detects `vercel.json`, building:
   - Frontend via `@vercel/static-build` from `frontend/`
   - FastAPI Backend via `@vercel/python` from `api/index.py` (importing `backend.app.main:app`)

---

### 2. FastAPI Entrypoint & Configuration

- **Confirmed Entrypoint**: `backend.app.main:app`
- **Serverless Wrapper**: [`api/index.py`](file:///Users/ashu/Documents/VMEG/Hackathons/SNIST/Red_Blue/api/index.py)
- **Metadata Spec**: [`pyproject.toml`](file:///Users/ashu/Documents/VMEG/Hackathons/SNIST/Red_Blue/pyproject.toml) (`entrypoint = "backend.app.main:app"`)

#### Environment Variables (Vercel Project Settings)

| Variable | Description | Example / Default |
|---|---|---|
| `FRONTEND_URL` | Allowed CORS origin URL | `https://your-project.vercel.app` |
| `REDBLUE_DB_PATH` | Event store SQLite path | `/tmp/blackbox.db` (auto-detected on Vercel) |
| `FEATHERLESS_API_KEY` | Featherless API key (Optional) | `featherless_sec_...` |
| `FEATHERLESS_BASE_URL` | Featherless API base URL | `https://api.featherless.ai/v1` |
| `FEATHERLESS_MODEL` | Featherless model | `NousResearch/Meta-Llama-3.1-8B-Instruct` |

> **Serverless Ephemeral Storage Note**: On Vercel Serverless Functions, `/tmp/` is writable per function execution, but filesystem storage is ephemeral across cold starts. The REDBLUE deterministic security engine, event collection, CHIMERA verification, and live session discovery operate seamlessly within invocations.

---

### 3. API Routing & Same-Origin Resolution

- **FastAPI Endpoints**: `/health`, `/events`, `/events/sessions`, `/events/run-demo`, `/incidents/analyze`, `/incidents/demo-scenario`, `/incidents/{id}/simulate`, `/incidents/{id}/defend`, `/investigate`.
- **Same-Origin Access**: When deployed on Vercel, leave `VITE_API_URL` empty or unset in Project Settings, allowing the React frontend to issue same-origin requests (`/events/sessions`). Vercel routes API paths directly to the Python function.

---

### 4. Attacker Package Remote Target Configuration

To test your deployed Vercel backend using the local synthetic attacker package:

```bash
# In attacker/.env or shell environment
TARGET_HOST=your-project.vercel.app
TARGET_PORT=443
TARGET_SCHEME=https
TARGET_ENDPOINT=/events/run-demo
```

Or pass a single target URL:

```bash
TARGET_URL=https://your-project.vercel.app/events/run-demo
```

#### Running Remote Scenarios

```bash
python3 scripts/send_malicious.py
python3 scripts/send_benign.py
```

---

# REDBLUE

### Adaptive Security & Forensic Intelligence for AI Agents & AI Automation

**Built for HackWave 3.0**



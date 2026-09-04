# BLACKBOX Knowledge Base

## 1. Core Problem Statement

Modern AI agents interact with tools, APIs, databases, documents, memory systems, other agents, and external web services. When an agent behaves incorrectly, succumbs to indirect prompt injection, or executes unauthorized actions, traditional logging systems only record isolated events rather than the entire execution lineage.

BLACKBOX solves this problem by reconstructing and reasoning about the AI agent's full execution behavior, enabling security teams to investigate incidents, measure blast radius impact, simulate counterfactual interventions, and deterministically verify defenses.

## 2. Solution Approach

BLACKBOX normalizes AI agent execution telemetry into a canonical **Universal AgentEvent** stream and constructs an **Execution Graph**. The Execution Graph is the central computational object of BLACKBOX upon which all security, impact analysis, and verification capabilities operate.

**End-to-End Conceptual Architecture:**
```text
AI Agent
  ↓
SDK / Adapter
  ↓
Event Collector
  ↓
Normalizer
  ↓
Universal AgentEvent
  ↓
Execution Graph
  ↓
┌───────────────────────────────────────────────┐
│ Detection                                     │
│ Impact / Blast Radius                         │
│ Evidence Extraction                           │
└───────────────────────────────────────────────┘
  ↓
Incident
  ↓
Understand
  ↓
Featherless Reasoning (LLM)
  ↓
Root Cause / Narrative / Evidence
  ↓
What-If / Counterfactual Simulation
  ↓
Intervention
  ↓
Defense
  ↓
CHIMERA / Re-Attack
  ↓
Verification
```

> **Note**: Phase 1.1 focuses exclusively on the **Execution Graph foundation** (converting events to nodes/edges, preserving event telemetry, representing execution chains/branches, deterministic traversal, and graph integrity).

## 3. Architectural Principle

### Deterministic Security
The Execution Graph, relationship tracking, reachability, blast radius, counterfactual simulation, and verification must be 100% **deterministic and evidence-based**.

### LLM Reasoning
LLMs (such as Featherless) are used downstream solely for interpretation, incident explanation, narrative generation, and reasoning over structured evidence. The LLM is **NOT** the authoritative source of graph structure or security truth.

## 4. Universal AgentEvent

### Target Architecture Contract
The Universal AgentEvent represents a normalized, framework-agnostic execution step.

**Target Fields:**
- `event_id`: Unique identifier for the event.
- `parent_event_id`: Optional ID of the parent event in the execution chain.
- `session_id`: Session or execution trace identifier.
- `agent_id`: Identifier of the agent.
- `event_type`: Event category (`agent_input`, `context_retrieval`, `decision`, `tool_call`, `tool_result`, `data_access`, `agent_message`, `external_request`, `policy_check`, `agent_output`).
- `source`: Origin entity or component.
- `target`: Target entity or component.
- `trust_level`: Security boundary (`trusted`, `internal`, `untrusted`, `external`).
- `permission`: Access level (`none`, `read`, `write`, `execute`, `export`, `admin`).
- `resource`: Target resource URI/identifier.
- `timestamp`: Event UTC timestamp.
- `metadata`: Arbitrary payload dictionary.

> **Status**: TARGET contract. The actual repository implementation must be inspected and verified before assuming exact structural parity.

## 5. Phase 1.1 Scope

### In-Scope (Phase 1.1):
- Execution Graph foundation setup
- Converting validated `AgentEvent` objects into graph nodes
- Preserving full event identity and payload data on graph nodes
- Representing parent-child execution relationships as directed edges (`parent_event_id -> event_id`)
- Supporting branching execution paths and multiple root nodes
- Supporting deterministic graph traversal
- Validating graph integrity (acyclic execution verification, dangling parent handling)
- Deterministic graph construction and unit testing

### Out-of-Scope (Phase 1.1):
- Prompt injection detection, attack detection, attack classification
- Risk/severity scoring, AEGIS blast radius, What-If simulation
- Counterfactual intervention optimization, CHIMERA re-attack, defense verification
- Featherless / LLM reasoning integration
- UI redesign
- Replacing P3 backend infrastructure or storage models

## 6. P1 / P3 Boundary

- **P3 Ownership**: Event generation, ingestion APIs, normalizers, event persistence/storage, and server infrastructure.
- **P1 Ownership**: Execution Graph, detection engines, evidence extraction, AEGIS impact, What-If simulation, intervention, and verification.
- **Boundary Rule**: P1 consumes `AgentEvent` data produced by P3. P1 must **NOT** create a competing event model or usurp P3's storage layer.

## 7. Execution Graph Data Model

- **Node Representation**: Every node in the graph is uniquely identified by `event_id` (`str`) and stores the complete, intact `AgentEvent` instance under attribute `node_data['event']`.
- **Edge Representation**: A directed edge is created from `parent_event_id` to `event_id` representing true causal execution lineage.
- **Core Technology**: `networkx.DiGraph`.

### Core Graph Invariants:
1. **Invariant 1: One event = one node** (Node identity = `event_id`).
2. **Invariant 2: Stable identity** (`event_id` is the immutable key across all operations).
3. **Invariant 3: Parent integrity** (No fabricated parents; missing parent triggers `GraphBuildError`).
4. **Invariant 4: Real relationships only** (Edge = `parent_event_id -> event_id`).
5. **Invariant 5: Original AgentEvent preservation** (The complete, un-truncated event model is preserved).
6. **Invariant 6: Deterministic execution** (Identical event input produces identical graph topology).
7. **Invariant 7: No security semantics** (Pure structural representation; no vulnerability scoring).

## 8. P1.1 — Execution Graph Foundation: DONE

Phase 1.1 is officially closed and verified.

- **AgentEvent Contract Compliance**: The graph builder consumes `app.events.schemas.AgentEvent` directly from P3.
- **P1 ↔ P3 Boundary Integrity**: P1 does NOT own event ingestion or storage. `backend/app/graph/` contains zero database/SQLAlchemy/SQLite dependencies and zero HTTP/FastAPI coupling.
- **Determinism & Forensic Validation**: Guaranteed by explicit list sorting across all traversal functions and strict 7-point structural verification in `validate_execution_graph`.
- **Scope Compliance**: Zero security detection, LLMs, risk scores, or future Phase 1.2+ scope leaked into P1.1.
- **Test Coverage**: 47 total automated unit and integration tests passing in `<0.4s`.

---

## 9. P1.2 Detection Architecture & Contracts

Phase 1.2 introduces the **Deterministic Detection Engine**, establishing the security contract between P1.1 (Execution Graph) and P2 (Understand / Featherless Reasoning Layer).

### Architectural Contracts
- **Input**: `ExecutionGraph` (`networkx.DiGraph`) constructed by P1.1.
- **Output**: `List[DetectionFinding]` containing structured forensic facts.
- **Detector Types**: `INDIRECT_PROMPT_INJECTION`, `TOOL_ABUSE`, `PRIVILEGE_VIOLATION`, `DATA_EXFILTRATION`.
- **Severity Levels**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (deterministic policy violation weight, NOT an LLM score).
- **Confidence**: Floating point value (0.0 to 1.0) indicating rule condition satisfaction score.

### Evidence Separation Principle
`DetectionFinding` explicitly separates deterministic forensic facts (`event_ids`, `evidence`, `graph_path`) from detector interpretation (`title`, `description`). This guarantees that P2 (Featherless) consumes immutable forensic evidence.

---

## Implementation Changelog

### [Phase 1.1 - Task 1] Workspace Setup & Repository Contract Inspection
- **Branch Setup**: Checked repository branches; created and switched to `backend` branch from `main`.
- **Knowledge Base**: Created `blackbox_knowledge_base.md` documenting core problem, architecture, deterministic principles, event contracts, phase scope, and team boundaries.
- **Repository Inspection**: Performed complete repository audit comparing existing codebase structure against the target architecture.

### [Phase 1.1 - Task 2] Define Graph Data Model, Invariants & Contracts
- **Dependency Update**: Added `networkx>=3.0` to root `requirements.txt`.
- **Graph Models & Invariants**: Created `backend/app/graph/models.py` defining `GraphBuildError`, `GraphValidationError`, `GraphPath`, and the 7 Core Graph Invariants.
- **Builder & Traversal Contracts**: Defined explicit signatures, return types, and docstrings in `backend/app/graph/builder.py` and `backend/app/graph/traversal.py`. Exported all contracts via `backend/app/graph/__init__.py`.
- **Knowledge Base Update**: Appended Execution Graph Data Model specification and updated `Implementation Changelog`.

### [Phase 1.1 - Task 3] Implement Execution Graph Builder
- **Graph Builder**: Implemented `build_execution_graph(events: list[AgentEvent]) -> nx.DiGraph` in `backend/app/graph/builder.py`.
- **Two-Pass Construction**: Pass 1 adds nodes with uniqueness checks; Pass 2 connects directed edges with parent existence checks.
- **Guarantees**: Ensures input order independence, supports multiple roots and branching traces, and preserves intact `AgentEvent` objects on nodes.
- **Pytest Unit Tests**: Created `backend/tests/test_graph_builder.py`.

### [Phase 1.1 - Task 4] Implement Deterministic Graph Traversal
- **Traversal Utilities**: Implemented structural graph navigation functions in `backend/app/graph/traversal.py`.
- **Determinism & Validation Guarantees**: Explicitly sorts all returned sets of event IDs alphabetically to eliminate non-deterministic set ordering. Validates node presence prior to traversal.
- **Pytest Unit Tests**: Created `backend/tests/test_graph_traversal.py`.

### [Phase 1.1 - Task 5] Implement Forensic Graph Validation & Integrity
- **Validation Module**: Created `backend/app/graph/validation.py` implementing `validate_execution_graph(events: list[AgentEvent], graph: nx.DiGraph) -> bool`.
- **Pytest Unit Tests**: Created `backend/tests/test_graph_validation.py`.

### [Phase 1.1 - Tasks 6 & 7] Integration Test Suite & Final Boundary Audit
- **End-to-End Integration Tests**: Created `backend/tests/test_graph_integration.py`.
- **Architectural Boundary Audit**: Verified zero DB/API leakage.
- **Phase Closure**: Appended Section 8 closing Phase 1.1 in `blackbox_knowledge_base.md`.

### [Phase 1.2.1] Define Detection Engine Architecture & Contracts
- **Detection Models & Enums**: Created `backend/app/detection/models.py` defining `DetectorType`, `Severity`, `DetectionFinding`, `DetectionError`, and `DetectionContractError`.
- **Interfaces & Engine**: Created `backend/app/detection/interfaces.py` (`BaseDetector`) and `backend/app/detection/engine.py` (`DetectionEngine`).
- **Pytest Contract Suite**: Created `backend/tests/test_detection_contracts.py`.

### [Phase 1.2.2] Implement Indirect Prompt Injection Detector
- **Prompt Injection Detector**: Created `backend/app/detection/detectors/prompt_injection.py` implementing `PromptInjectionDetector(BaseDetector)`.
- **Pytest Detector Suite**: Created `backend/tests/test_prompt_injection.py`.

### [Phase 1.2.3] Implement Tool Abuse & Privilege Violation Detector
- **Privilege Detector**: Created `backend/app/detection/detectors/privilege_violation.py` implementing `PrivilegeViolationDetector(BaseDetector)`.
- **Pytest Detector Suite**: Created `backend/tests/test_privilege_violation.py`.

### [Phase 1.2.4] Implement Data Exfiltration Detector
- **Data Exfiltration Detector**: Created `backend/app/detection/detectors/data_exfiltration.py` implementing `DataExfiltrationDetector(BaseDetector)`.
- **Deterministic Lineage Rule**:
  - **Sensitive Data Access**: Identifies `DATA_ACCESS`/`RETRIEVAL` nodes with metadata classification `HIGH`/`CRITICAL` or sensitive resource naming (`"sensitive"`, `"critical"`, `"pii"`, `"secret"`, `"credentials"`, `"financial"`). Ignores `LOW`/`PUBLIC` data.
  - **Downstream Lineage Traversal**: Uses `nx.descendants(graph, s_node)` and `nx.has_path(graph, s_node, d_node)` to trace directed paths to downstream `ACTION`/`TOOL_CALL`/`EXTERNAL_REQUEST` boundary nodes.
  - **Exfiltration Boundary Trigger**: Flags finding if the downstream target is `UNTRUSTED`/`EXTERNAL` (or HTTP endpoint/`export` action).
  - **Finding Construction**: Emits `DetectionFinding` with `confidence=1.0`, severity mapped to resource sensitivity (`CRITICAL` vs `HIGH`), complete `graph_path`, and detailed `evidence` dictionary.
- **Pytest Detector Suite**: Created `backend/tests/test_data_exfiltration.py` covering True Positives (exfil path), True Negatives (public data), True Negatives (internal move), True Negatives (disconnected branches), and multi-run Determinism (5 test functions, 68 total suite tests passing in 0.38s).
- **Knowledge Base Update**: Documented Task P1.2.4 completion and rule definition in `Implementation Changelog`.

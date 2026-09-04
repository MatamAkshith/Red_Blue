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

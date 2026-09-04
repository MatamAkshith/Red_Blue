"""Detection models, enums, and exceptions contract.

DETERMINISTIC SECURITY PRINCIPLE:
- Severity represents deterministic policy/rule violation weight (LOW, MEDIUM, HIGH, CRITICAL), NEVER an LLM score.
- Confidence represents deterministic rule condition satisfaction (0.0 to 1.0), NOT model heuristics or vibes.
- Forensic facts (event_ids, evidence, graph_path) are strictly derived from the Execution Graph and preserved without modification.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DetectorType(str, Enum):
    """Canonical categories of deterministic security detectors."""
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    TOOL_ABUSE = "TOOL_ABUSE"
    PRIVILEGE_VIOLATION = "PRIVILEGE_VIOLATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


class Severity(str, Enum):
    """Canonical deterministic severity levels based on policy violation weight."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionFinding(BaseModel):
    """Canonical security finding produced by a deterministic detector.

    Separates deterministic forensic facts (event_ids, evidence, graph_path) from detector interpretation (title, description).
    """

    finding_id: str = Field(..., description="Unique identifier for the finding")
    detector_type: DetectorType = Field(..., description="Category of the triggering detector")
    title: str = Field(..., description="Detector interpretation summary")
    description: str = Field(..., description="Detector interpretation details")
    severity: Severity = Field(..., description="Deterministic policy violation weight (LOW, MEDIUM, HIGH, CRITICAL)")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Deterministic match score (0.0-1.0) indicating rule condition satisfaction",
    )
    event_ids: List[str] = Field(..., min_length=1, description="Exact list of supporting AgentEvent IDs (concrete evidence)")
    graph_path: List[str] = Field(default_factory=list, description="Sequence of event IDs representing the execution path")
    source: Optional[str] = Field(None, description="Originating entity or resource involved in the finding")
    target: Optional[str] = Field(None, description="Target entity or sensitive resource involved in the finding")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Structured forensic facts extracted from graph nodes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or key-value metadata")

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class DetectionError(Exception):
    """Raised when an error occurs during detection engine execution or graph analysis."""
    pass


class DetectionContractError(Exception):
    """Raised when a detector returns a finding that violates the detection contract."""
    pass

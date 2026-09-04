"""Detection engine orchestrator."""

from __future__ import annotations

from typing import Dict, List
import networkx as nx

from .interfaces import BaseDetector
from .models import DetectionError, DetectionFinding, Severity

SEVERITY_PRIORITY: Dict[str, int] = {
    Severity.CRITICAL.value if hasattr(Severity.CRITICAL, "value") else str(Severity.CRITICAL): 0,
    Severity.HIGH.value if hasattr(Severity.HIGH, "value") else str(Severity.HIGH): 1,
    Severity.MEDIUM.value if hasattr(Severity.MEDIUM, "value") else str(Severity.MEDIUM): 2,
    Severity.LOW.value if hasattr(Severity.LOW, "value") else str(Severity.LOW): 3,
}


class DetectionEngine:
    """Orchestrator for executing registered deterministic detectors over an Execution Graph."""

    def __init__(self) -> None:
        self._detectors: List[BaseDetector] = []

    @property
    def detectors(self) -> List[BaseDetector]:
        """Return the list of currently registered detectors."""
        return list(self._detectors)

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a new security detector with the engine.

        Args:
            detector: Instance of a subclass of BaseDetector.
        """
        if not isinstance(detector, BaseDetector):
            raise DetectionError(f"Detector must inherit from BaseDetector, got {type(detector)}")
        self._detectors.append(detector)

    def run(self, graph: nx.DiGraph) -> List[DetectionFinding]:
        """Execute all registered detectors against the provided execution graph.

        Args:
            graph: The NetworkX directed execution graph.

        Returns:
            List[DetectionFinding]: Stably sorted list of findings across all detectors.

        Raises:
            DetectionError: If graph is None or invalid.
        """
        if graph is None:
            raise DetectionError("Execution graph cannot be None")
        if not isinstance(graph, nx.DiGraph):
            raise DetectionError(f"Invalid graph object: expected nx.DiGraph, got {type(graph)}")

        if len(graph.nodes) == 0:
            return []

        all_findings: List[DetectionFinding] = []

        for detector in self._detectors:
            try:
                findings = detector.detect(graph)
                if findings:
                    all_findings.extend(findings)
            except Exception as exc:
                if isinstance(exc, DetectionError):
                    raise
                raise DetectionError(f"Detector '{detector.__class__.__name__}' failed: {exc}") from exc

        # Stable, deterministic sorting: Priority by Severity (descending), then by finding_id, then by primary event_id
        def sort_key(finding: DetectionFinding) -> tuple:
            sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            priority = SEVERITY_PRIORITY.get(sev_str, 99)
            primary_event = finding.event_ids[0] if finding.event_ids else ""
            return (priority, finding.finding_id, primary_event)

        all_findings.sort(key=sort_key)
        return all_findings

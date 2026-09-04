"""Abstract base class interface for security detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List
import networkx as nx

from .models import DetectionFinding, DetectorType


class BaseDetector(ABC):
    """Abstract base class for all deterministic security detectors."""

    detector_type: DetectorType

    @abstractmethod
    def detect(self, graph: nx.DiGraph) -> List[DetectionFinding]:
        """Analyze an ExecutionGraph and return detected security findings.

        Args:
            graph: The NetworkX directed execution graph.

        Returns:
            List[DetectionFinding]: List of deterministic findings produced by the detector.
        """
        raise NotImplementedError("Subclasses must implement detect()")

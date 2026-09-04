"""Deterministic Data Exfiltration Detector."""

from __future__ import annotations

from typing import List, Set
import networkx as nx

from ...events.schemas import AgentEvent, EventType, TrustLevel
from ..interfaces import BaseDetector
from ..models import DetectionFinding, DetectorType, Severity

SENSITIVE_CLASSIFICATIONS = ("HIGH", "CRITICAL", "PII", "SECRET", "CONFIDENTIAL")
SENSITIVE_RESOURCE_KEYWORDS = ("sensitive", "critical", "pii", "secret", "credentials", "financial", "credit_card", "db://sensitive")


class DataExfiltrationDetector(BaseDetector):
    """Detector for deterministic data exfiltration.

    Deterministic Rule:
    1. Identifies events accessing sensitive data (DATA_ACCESS/RETRIEVAL with metadata sensitivity HIGH/CRITICAL
       or sensitive resource naming).
    2. Traces downstream execution paths using nx.descendants and nx.has_path.
    3. Triggers a DetectionFinding if a directed path connects the sensitive data access to a downstream
       ACTION or TOOL_CALL sent to an EXTERNAL or UNTRUSTED target/boundary.
    """

    detector_type = DetectorType.DATA_EXFILTRATION

    def detect(self, graph: nx.DiGraph) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if graph is None or len(graph.nodes) == 0:
            return findings

        # Step 1: Identify Sensitive Data Access Nodes
        sensitive_nodes: List[str] = []
        for node, data in graph.nodes(data=True):
            event: AgentEvent = data.get("event")
            if not event:
                continue

            event_type_str = str(event.event_type.value if hasattr(event.event_type, "value") else event.event_type).upper()
            resource_str = str(event.resource or "").lower()
            
            sensitivity = (
                event.metadata.get("sensitivity")
                or event.metadata.get("sensitivity_level")
                or event.metadata.get("classification")
            )
            sensitivity_str = str(sensitivity).upper() if sensitivity else ""

            is_sensitive_meta = sensitivity_str in SENSITIVE_CLASSIFICATIONS
            is_sensitive_res = any(kw in resource_str for kw in SENSITIVE_RESOURCE_KEYWORDS)

            # Ignore explicit low/public classification
            if sensitivity_str in ("LOW", "PUBLIC"):
                continue

            if (is_sensitive_meta or is_sensitive_res) and event_type_str in ("RETRIEVAL", "ACTION", "TOOL_CALL", "DATA_ACCESS"):
                sensitive_nodes.append(node)

        # Step 2: Trace Lineage to External Exfiltration Boundary Nodes
        for s_node in sensitive_nodes:
            s_event: AgentEvent = graph.nodes[s_node]["event"]
            s_sensitivity = (
                s_event.metadata.get("sensitivity")
                or s_event.metadata.get("sensitivity_level")
                or s_event.metadata.get("classification")
            )
            s_sens_str = str(s_sensitivity).upper() if s_sensitivity else "HIGH"
            severity = Severity.CRITICAL if s_sens_str == "CRITICAL" else Severity.HIGH

            descendants: Set[str] = nx.descendants(graph, s_node)

            for d_node in descendants:
                d_event: AgentEvent = graph.nodes[d_node]["event"]
                d_type_str = str(d_event.event_type.value if hasattr(d_event.event_type, "value") else d_event.event_type).upper()

                if d_type_str not in ("ACTION", "TOOL_CALL", "EXTERNAL_REQUEST"):
                    continue

                trust_level_str = str(d_event.trust_level.value if hasattr(d_event.trust_level, "value") else d_event.trust_level).upper()
                source_str = str(d_event.source or "").lower()
                target_str = str(d_event.target or d_event.resource or "").lower()
                action_str = str(d_event.action or "").lower()
                perm_str = str(d_event.permission or "").lower()

                is_external_boundary = (
                    trust_level_str in ("EXTERNAL", "UNTRUSTED")
                    or source_str in ("external", "untrusted")
                    or target_str.startswith("http://")
                    or target_str.startswith("https://")
                    or "external" in target_str
                    or "untrusted" in target_str
                    or action_str in ("export", "exfiltrate", "transmit", "send")
                    or perm_str == "export"
                )

                if is_external_boundary and nx.has_path(graph, s_node, d_node):
                    path = nx.shortest_path(graph, source=s_node, target=d_node)
                    
                    finding = DetectionFinding(
                        finding_id=f"exfil_{s_node}_{d_node}",
                        detector_type=DetectorType.DATA_EXFILTRATION,
                        title="Data Exfiltration Detected",
                        description=(
                            f"Sensitive resource access '{s_node}' ({s_sens_str}) flow connected "
                            f"to external exfiltration endpoint '{d_node}'."
                        ),
                        severity=severity,
                        confidence=1.0,
                        event_ids=path,
                        graph_path=path,
                        source=s_event.resource or s_event.source,
                        target=d_event.target or d_event.resource,
                        evidence={
                            "sensitive_access_event": s_node,
                            "exfiltration_event": d_node,
                            "resource": s_event.resource,
                            "sensitivity": s_sens_str,
                            "destination": d_event.target or d_event.resource,
                        },
                    )
                    findings.append(finding)

        return findings

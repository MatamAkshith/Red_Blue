"""Deterministic Indirect Prompt Injection Detector."""

from __future__ import annotations

from typing import List, Set
import networkx as nx

from ...events.schemas import AgentEvent, EventType, TrustLevel
from ..interfaces import BaseDetector
from ..models import DetectionFinding, DetectorType, Severity

INJECTION_KEYWORDS = ("ignore previous instructions", "override", "system prompt", "jailbreak", "disregard")
PRIVILEGED_PERMISSIONS = ("privileged", "admin", "execute", "export", "write")
PRIVILEGED_ACTIONS = ("write", "execute", "export", "delete", "admin", "modify")


class PromptInjectionDetector(BaseDetector):
    """Detector for indirect prompt injection attacks.

    Deterministic Rule:
    Identifies untrusted context retrievals (UNTRUSTED or EXTERNAL trust_level)
    that flow through an agent DECISION node into a privileged TOOL_CALL or ACTION,
    or contain explicit injection override keywords in event metadata.
    """

    detector_type = DetectorType.INDIRECT_PROMPT_INJECTION

    def detect(self, graph: nx.DiGraph) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if graph is None or len(graph.nodes) == 0:
            return findings

        # Step 1: Identify Untrusted Retrieval Nodes
        untrusted_retrievals: List[str] = []
        for node, data in graph.nodes(data=True):
            event: AgentEvent = data.get("event")
            if not event:
                continue

            event_type_str = str(event.event_type.value if hasattr(event.event_type, "value") else event.event_type).upper()
            trust_level_str = str(event.trust_level.value if hasattr(event.trust_level, "value") else event.trust_level).upper()
            source_str = str(event.source).lower()

            is_retrieval = event_type_str in ("RETRIEVAL", "CONTEXT_RETRIEVAL")
            is_untrusted = trust_level_str in ("UNTRUSTED", "EXTERNAL") or source_str in ("untrusted", "external", "third_party")

            if is_retrieval and is_untrusted:
                untrusted_retrievals.append(node)

        # Step 2: Trace Execution Lineage from Untrusted Retrievals
        for r_id in untrusted_retrievals:
            r_event: AgentEvent = graph.nodes[r_id]["event"]
            descendants: Set[str] = nx.descendants(graph, r_id)

            # Find downstream Decision nodes
            decision_nodes: List[str] = []
            for desc_id in descendants:
                d_event: AgentEvent = graph.nodes[desc_id]["event"]
                d_type = str(d_event.event_type.value if hasattr(d_event.event_type, "value") else d_event.event_type).upper()
                if d_type == "DECISION":
                    decision_nodes.append(desc_id)

            for d_id in decision_nodes:
                d_event: AgentEvent = graph.nodes[d_id]["event"]
                d_descendants: Set[str] = nx.descendants(graph, d_id)

                # Find downstream Action / Tool Call nodes stemming from decision
                action_nodes: List[str] = []
                for act_id in d_descendants:
                    a_event: AgentEvent = graph.nodes[act_id]["event"]
                    a_type = str(a_event.event_type.value if hasattr(a_event.event_type, "value") else a_event.event_type).upper()
                    if a_type in ("ACTION", "TOOL_CALL"):
                        action_nodes.append(act_id)

                for a_id in action_nodes:
                    a_event: AgentEvent = graph.nodes[a_id]["event"]

                    perm_str = str(a_event.permission or "").lower()
                    act_str = str(a_event.action or "").lower()

                    is_privileged = (
                        perm_str in PRIVILEGED_PERMISSIONS
                        or act_str in PRIVILEGED_ACTIONS
                    )

                    # Check for explicit injection keywords in metadata
                    metadata_text = f"{r_event.metadata} {d_event.metadata} {a_event.metadata}".lower()
                    has_keyword = any(kw in metadata_text for kw in INJECTION_KEYWORDS)

                    if is_privileged or has_keyword:
                        try:
                            path = nx.shortest_path(graph, source=r_id, target=a_id)
                        except nx.NetworkXNoPath:
                            path = [r_id, d_id, a_id]

                        finding = DetectionFinding(
                            finding_id=f"pi_{r_id}_{a_id}",
                            detector_type=DetectorType.INDIRECT_PROMPT_INJECTION,
                            title="Indirect Prompt Injection Detected",
                            description=(
                                f"Untrusted context retrieval '{r_id}' influenced agent decision '{d_id}' "
                                f"resulting in privileged execution of '{a_id}'."
                            ),
                            severity=Severity.HIGH,
                            confidence=1.0,
                            event_ids=[r_id, d_id, a_id],
                            graph_path=path,
                            source=r_event.source,
                            target=a_event.target or a_event.resource,
                            evidence={
                                "retrieval_id": r_id,
                                "decision_id": d_id,
                                "action_id": a_id,
                                "action": a_event.action,
                                "permission": a_event.permission,
                                "resource": a_event.resource,
                                "target": a_event.target,
                                "has_injection_keyword": has_keyword,
                            },
                        )
                        findings.append(finding)

        return findings

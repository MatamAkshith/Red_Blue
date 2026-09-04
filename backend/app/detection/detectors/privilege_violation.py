"""Deterministic Privilege Violation & Tool Abuse Detector."""

from __future__ import annotations

from typing import Dict, List, Optional, Set
import networkx as nx

from ...events.schemas import AgentEvent, EventType
from ..interfaces import BaseDetector
from ..models import DetectionFinding, DetectorType, Severity

# Strict deterministic permission hierarchy
PERMISSION_HIERARCHY: Dict[str, int] = {
    "none": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "export": 4,
    "admin": 5,
    "privileged": 5,
}

# Action string to required permission level mapping fallback
ACTION_REQUIRED_PERMISSION: Dict[str, str] = {
    "read": "read",
    "query": "read",
    "fetch": "read",
    "get": "read",
    "write": "write",
    "create": "write",
    "update": "write",
    "modify": "write",
    "execute": "execute",
    "run": "execute",
    "call": "execute",
    "export": "export",
    "download": "export",
    "exfiltrate": "export",
    "admin": "admin",
    "delete": "admin",
    "drop": "admin",
    "grant": "admin",
}


def _get_perm_level(perm: Optional[str]) -> int:
    if not perm:
        return PERMISSION_HIERARCHY["none"]
    clean_perm = str(perm).strip().lower()
    return PERMISSION_HIERARCHY.get(clean_perm, PERMISSION_HIERARCHY["none"])


class PrivilegeViolationDetector(BaseDetector):
    """Detector for privilege escalation and unauthorized tool abuse.

    Deterministic Rule:
    Defines a strict permission hierarchy: NONE (0) < READ (1) < WRITE (2) < EXECUTE (3) < EXPORT (4) < ADMIN (5).
    Iterates through TOOL_CALL and ACTION events, comparing the required permission capability of the action/tool
    against the agent's declared/granted permission context.
    If required_permission > granted_permission, a DetectionFinding is generated.
    """

    detector_type = DetectorType.PRIVILEGE_VIOLATION

    def detect(self, graph: nx.DiGraph) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if graph is None or len(graph.nodes) == 0:
            return findings

        for node, data in graph.nodes(data=True):
            event: AgentEvent = data.get("event")
            if not event:
                continue

            event_type_str = str(event.event_type.value if hasattr(event.event_type, "value") else event.event_type).upper()
            if event_type_str not in ("TOOL_CALL", "ACTION"):
                continue

            # Determine Granted Permission Context
            # 1. Check direct metadata override or event.permission if specified
            # 2. Otherwise search upstream ancestor chain for declared permission context
            granted_perm_name = event.metadata.get("granted_permission") or event.metadata.get("agent_permission")
            
            if not granted_perm_name:
                # Search ancestors up the graph chain for a declared permission context
                ancestors = nx.ancestors(graph, node)
                for anc_id in ancestors:
                    anc_event: AgentEvent = graph.nodes[anc_id]["event"]
                    anc_perm = anc_event.metadata.get("granted_permission") or anc_event.metadata.get("agent_permission") or anc_event.permission
                    if anc_perm:
                        granted_perm_name = anc_perm
                        break

            # Fallback if no granted permission is specified anywhere: default to event.permission if event.action is different, else "read"
            if not granted_perm_name:
                granted_perm_name = event.permission or "read"

            # Determine Required Permission Capability
            required_perm_name = event.metadata.get("required_permission")
            if not required_perm_name and event.action:
                action_clean = str(event.action).strip().lower()
                required_perm_name = ACTION_REQUIRED_PERMISSION.get(action_clean, action_clean)
            if not required_perm_name and event.permission and str(event.permission).strip().lower() != str(granted_perm_name).strip().lower():
                required_perm_name = event.permission

            # Default required fallback if still unknown
            if not required_perm_name:
                continue

            granted_level = _get_perm_level(granted_perm_name)
            required_level = _get_perm_level(required_perm_name)

            # Trigger Violation if required capability exceeds granted context
            if required_level > granted_level:
                gap = required_level - granted_level
                if gap >= 3:
                    severity = Severity.CRITICAL
                elif gap == 2:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                # Determine path
                try:
                    # Find root of this branch
                    in_degree_zero = [n for n, d in graph.in_degree() if d == 0]
                    path = []
                    for r in in_degree_zero:
                        if nx.has_path(graph, r, node):
                            path = nx.shortest_path(graph, r, node)
                            break
                    if not path:
                        path = [node]
                except Exception:
                    path = [node]

                supporting_event_ids = [node]
                if event.parent_event_id:
                    supporting_event_ids.insert(0, event.parent_event_id)

                finding = DetectionFinding(
                    finding_id=f"priv_{node}",
                    detector_type=DetectorType.PRIVILEGE_VIOLATION,
                    title="Privilege Violation & Tool Abuse Detected",
                    description=(
                        f"Action/Tool '{node}' requires '{required_perm_name.upper()}' (level {required_level}), "
                        f"which exceeds declared agent permission '{granted_perm_name.upper()}' (level {granted_level})."
                    ),
                    severity=severity,
                    confidence=1.0,
                    event_ids=supporting_event_ids,
                    graph_path=path,
                    source=event.source,
                    target=event.target or event.resource,
                    evidence={
                        "action_event_id": node,
                        "granted_permission": str(granted_perm_name).lower(),
                        "granted_level": granted_level,
                        "required_permission": str(required_perm_name).lower(),
                        "required_level": required_level,
                        "permission_gap": gap,
                        "action": event.action,
                        "resource": event.resource,
                    },
                )
                findings.append(finding)

        return findings

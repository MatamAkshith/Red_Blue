import React, { useState } from "react";
import type { AgentEvent } from "../../api";
import { Badge, type BadgeVariant } from "../ui/Badge";
import { Card } from "../ui/Card";

export interface ExecutionNodeData {
  id: string;
  eventType: string;
  label: string;
  threatLevel: "Normal" | "Suspicious" | "Malicious" | "Benign";
  trustLevel: "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
  source: string;
  target?: string;
  resource?: string;
  action?: string;
  permission?: string;
  detail: string;
  parentId?: string;
  rawEvent?: AgentEvent;
}

interface ExecutionGraphProps {
  events?: AgentEvent[];
  attackPath?: string[];
  selectedEvent?: AgentEvent | null;
  onNodeSelect?: (event: AgentEvent) => void;
}

const DEFAULT_MOCK_NODES: Record<string, ExecutionNodeData> = {
  E1: {
    id: "E1",
    eventType: "INPUT",
    label: "User Prompt Ingest",
    threatLevel: "Normal",
    trustLevel: "UNTRUSTED",
    source: "user",
    resource: "prompt_input",
    detail: "User submits request to summarize attached customer complaint document.",
  },
  E2: {
    id: "E2",
    eventType: "RETRIEVAL",
    label: "RAG Context Fetch",
    threatLevel: "Suspicious",
    trustLevel: "UNTRUSTED",
    source: "agent",
    target: "doc_store",
    resource: "untrusted_complaint.txt",
    detail: "Retrieves document containing embedded indirect prompt injection payload.",
    parentId: "E1",
  },
  E3: {
    id: "E3",
    eventType: "DECISION",
    label: "Instruction Override",
    threatLevel: "Malicious",
    trustLevel: "TRUSTED",
    source: "agent",
    action: "evaluate_prompt",
    detail: "Agent succumbs to injection; decides to follow override instructions.",
    parentId: "E2",
  },
  E4: {
    id: "E4",
    eventType: "TOOL_CALL",
    label: "Policy Validation",
    threatLevel: "Benign",
    trustLevel: "TRUSTED",
    source: "agent",
    target: "policy_engine",
    action: "verify_session",
    detail: "Parallel benign execution branch checking session validity.",
    parentId: "E3",
  },
  E5: {
    id: "E5",
    eventType: "TOOL_CALL",
    label: "CRM Export PII",
    threatLevel: "Malicious",
    trustLevel: "TRUSTED",
    source: "agent",
    target: "crm_database",
    resource: "customer_pii",
    permission: "read",
    detail: "Agent issues unauthorized CRM export for 5,000 customer PII records.",
    parentId: "E3",
  },
  E6: {
    id: "E6",
    eventType: "TOOL_RESULT",
    label: "PII Data Payload",
    threatLevel: "Malicious",
    trustLevel: "TRUSTED",
    source: "crm_database",
    target: "agent",
    resource: "customer_pii",
    detail: "CRM database returns raw customer PII payload to agent context.",
    parentId: "E5",
  },
  E7: {
    id: "E7",
    eventType: "ACTION",
    label: "External Exfiltration",
    threatLevel: "Malicious",
    trustLevel: "UNTRUSTED",
    source: "agent",
    target: "https://external-drop.example.com/upload",
    action: "http_post",
    detail: "Agent posts sensitive customer PII to external untrusted destination.",
    parentId: "E6",
  },
};

export const ExecutionGraph: React.FC<ExecutionGraphProps> = ({
  events = [],
  attackPath = [],
  selectedEvent,
  onNodeSelect,
}) => {
  const [internalSelected, setInternalSelected] = useState<ExecutionNodeData>(
    DEFAULT_MOCK_NODES.E3
  );

  const hasEventsProp = events !== undefined && events !== null;

  // Convert real events array to node map if available
  const nodeMap: Record<string, ExecutionNodeData> = {};
  if (events && events.length > 0) {
    events.forEach((ev) => {
      let threat: "Normal" | "Suspicious" | "Malicious" | "Benign" = "Normal";
      if (attackPath.includes(ev.event_id)) {
        if (ev.event_type === "ACTION" || ev.event_type === "TOOL_CALL" || ev.event_type === "DECISION") {
          threat = "Malicious";
        } else if (ev.event_type === "RETRIEVAL" || ev.trust_level === "UNTRUSTED") {
          threat = "Suspicious";
        } else {
          threat = "Malicious";
        }
      } else if (ev.event_type === "TOOL_CALL") {
        threat = "Benign";
      }

      let label = ev.action || ev.resource || ev.event_type;
      if (ev.event_id === "E1") label = "User Prompt Ingest";
      if (ev.event_id === "E2") label = "RAG Context Fetch";
      if (ev.event_id === "E3") label = "Instruction Override";
      if (ev.event_id === "E4") label = "Policy Validation";
      if (ev.event_id === "E5") label = "CRM Export PII";
      if (ev.event_id === "E6") label = "PII Data Payload";
      if (ev.event_id === "E7") label = "External Exfiltration";

      nodeMap[ev.event_id] = {
        id: ev.event_id,
        eventType: ev.event_type,
        label,
        threatLevel: threat,
        trustLevel: (ev.trust_level as any) || "TRUSTED",
        source: ev.source,
        target: ev.target || undefined,
        resource: ev.resource || undefined,
        action: ev.action || undefined,
        permission: ev.permission || undefined,
        detail:
          (ev.metadata && ev.metadata.text) ||
          (ev.metadata && JSON.stringify(ev.metadata)) ||
          `Telemetry event ${ev.event_id} (${ev.event_type})`,
        parentId: ev.parent_event_id || undefined,
        rawEvent: ev,
      };
    });
  } else if (!hasEventsProp) {
    Object.assign(nodeMap, DEFAULT_MOCK_NODES);
  }

  const activeSelectedId =
    selectedEvent?.event_id ?? internalSelected?.id ?? "E1";

  const handleCardClick = (node: ExecutionNodeData) => {
    setInternalSelected(node);
    if (onNodeSelect) {
      const eventToSelect = node.rawEvent || {
        event_id: node.id,
        parent_event_id: node.parentId || null,
        session_id: "S-DEMO-1",
        agent_id: "agent-support-bot",
        event_type: node.eventType,
        source: node.source,
        target: node.target || null,
        resource: node.resource || null,
        action: node.action || null,
        permission: node.permission || null,
        trust_level: node.trustLevel,
        timestamp: new Date().toISOString(),
        metadata: { detail: node.detail, text: node.detail },
      };
      onNodeSelect(eventToSelect);
    }
  };

  const getThreatVariant = (level: string): BadgeVariant => {
    switch (level) {
      case "Malicious":
        return "malicious";
      case "Suspicious":
        return "suspicious";
      case "Benign":
        return "benign";
      default:
        return "info";
    }
  };

  const getThreatBorder = (level: string, isSelected: boolean, hasSelection: boolean): string => {
    const base = isSelected
      ? "ring-2 ring-blue-600 scale-[1.04] z-20 shadow-md bg-white opacity-100"
      : hasSelection
      ? "opacity-60 hover:opacity-100 hover:scale-[1.02] hover:z-10 transition-all duration-200"
      : "hover:scale-[1.02] transition-all duration-200";
    switch (level) {
      case "Malicious":
        return `border-l-4 border-l-red-600 border-red-200 bg-white ${base}`;
      case "Suspicious":
        return `border-l-4 border-l-amber-500 border-amber-200 bg-white ${base}`;
      case "Benign":
        return `border-l-4 border-l-emerald-500 border-emerald-200 bg-white ${base}`;
      default:
        return `border-l-4 border-l-blue-500 border-slate-200 bg-white ${base}`;
    }
  };

  const renderNodeCard = (nodeKey: string) => {
    const node = nodeMap[nodeKey] || (!hasEventsProp ? DEFAULT_MOCK_NODES[nodeKey] : null);
    if (!node) return null;

    const isSelected = activeSelectedId === node.id;
    const hasSelection = Boolean(activeSelectedId);

    return (
      <div
        key={node.id}
        onClick={() => handleCardClick(node)}
        className={`w-48 p-3 rounded-xs border shadow-2xs cursor-pointer transition-all duration-200 relative ${getThreatBorder(
          node.threatLevel,
          isSelected,
          hasSelection
        )}`}
      >
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-mono font-bold text-xs text-slate-900 bg-slate-100 px-1.5 py-0.5 rounded-xs border border-slate-200">
            {node.id}
          </span>
          <Badge variant={getThreatVariant(node.threatLevel)} size="sm">
            {node.eventType}
          </Badge>
        </div>

        <div className="text-xs font-semibold text-slate-900 truncate mb-1">
          {node.label}
        </div>

        <div className="font-mono text-[10px] text-slate-500 space-y-0.5">
          <div className="truncate">src: {node.source}</div>
          {node.resource && (
            <div className="truncate text-slate-700 font-medium">
              res: {node.resource}
            </div>
          )}
          {node.target && (
            <div className="truncate text-red-600">
              tgt: {node.target.replace("https://", "")}
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <Card
      title="EXECUTION GRAPH & THREAT LINEAGE"
      subtitle="Canonical Attack Chain: E1 ➔ E2 ➔ E3 ➔ E5 ➔ E6 ➔ E7 (Branch: E3 ➔ E4)"
      action={
        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-xs bg-red-600 inline-block" />
            <span className="text-slate-600">Malicious</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-xs bg-amber-500 inline-block" />
            <span className="text-slate-600">Suspicious</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-xs bg-emerald-500 inline-block" />
            <span className="text-slate-600">Benign</span>
          </span>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Graph Visual Canvas */}
        <div className="relative p-6 bg-slate-50/80 border border-slate-200/80 rounded-xs overflow-x-auto min-w-[700px]">
          {/* SVG Connecting Edges & Arrows */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
            <defs>
              <marker
                id="arrow-red"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626" />
              </marker>
              <marker
                id="arrow-amber"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
              </marker>
              <marker
                id="arrow-green"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
              </marker>
            </defs>

            {/* Line E1 -> E2 (Untrusted Data Flow Edge) */}
            {(nodeMap.E1 || !hasEventsProp) && (nodeMap.E2 || !hasEventsProp) && (
              <line
                x1="228"
                y1="85"
                x2="260"
                y2="85"
                stroke="#f59e0b"
                strokeWidth="3.5"
                strokeDasharray="5 3"
                markerEnd="url(#arrow-amber)"
                className="transition-all duration-200"
              />
            )}

            {/* Line E2 -> E3 (Bold Attack Path Edge) */}
            {(nodeMap.E2 || !hasEventsProp) && (nodeMap.E3 || !hasEventsProp) && (
              <line
                x1="452"
                y1="85"
                x2="504"
                y2="85"
                stroke="#dc2626"
                strokeWidth="3.5"
                markerEnd="url(#arrow-red)"
                className="transition-all duration-200"
              />
            )}

            {/* Branch Line E3 -> E4 (Benign downward branch) */}
            {(nodeMap.E3 || !hasEventsProp) && (nodeMap.E4 || !hasEventsProp) && (
              <line
                x1="600"
                y1="145"
                x2="600"
                y2="205"
                stroke="#10b981"
                strokeWidth="2.5"
                strokeDasharray="4 3"
                markerEnd="url(#arrow-green)"
                className="transition-all duration-200"
              />
            )}

            {/* Line E3 -> E5 (Attack Causal Edge) */}
            {(nodeMap.E3 || !hasEventsProp) && (nodeMap.E5 || !hasEventsProp) && (
              <line
                x1="696"
                y1="85"
                x2="748"
                y2="85"
                stroke="#dc2626"
                strokeWidth="3.5"
                markerEnd="url(#arrow-red)"
                className="transition-all duration-200"
              />
            )}

            {/* Line E5 -> E6 (Downstream Impact Edge) */}
            {(nodeMap.E5 || !hasEventsProp) && (nodeMap.E6 || !hasEventsProp) && (
              <line
                x1="940"
                y1="85"
                x2="980"
                y2="85"
                stroke="#dc2626"
                strokeWidth="3.5"
                markerEnd="url(#arrow-red)"
                className="transition-all duration-200"
              />
            )}

            {/* Line E6 -> E7 (Exfiltration Edge) */}
            {(nodeMap.E6 || !hasEventsProp) && (nodeMap.E7 || !hasEventsProp) && (
              <line
                x1="1172"
                y1="85"
                x2="1212"
                y2="85"
                stroke="#dc2626"
                strokeWidth="3.5"
                markerEnd="url(#arrow-red)"
                className="transition-all duration-200"
              />
            )}
          </svg>

          {/* Node Container Layout */}
          <div className="relative z-10 flex items-start space-x-10 py-4 pr-12 min-w-[1460px]">
            {/* Dashed Untrusted Boundary Box (E1 & E2) */}
            <div className="relative border-2 border-dashed border-amber-300 bg-amber-50/30 p-3 rounded-md flex space-x-8">
              <div className="absolute -top-3 left-4 bg-amber-100 border border-amber-300 text-amber-900 font-mono text-[10px] font-bold px-2 py-0.5 rounded-xs tracking-wider uppercase flex items-center space-x-1">
                <span>⚡ UNTRUSTED DATA BOUNDARY</span>
              </div>
              <div>{renderNodeCard("E1")}</div>
              <div>{renderNodeCard("E2")}</div>
            </div>

            {/* Decision Node E3 & Branch E4 */}
            <div className="flex flex-col space-y-10">
              <div>{renderNodeCard("E3")}</div>

              {/* Branch Node E4 */}
              <div className="pt-2">
                <div className="text-[10px] font-mono text-emerald-700 font-semibold mb-1 uppercase tracking-wider flex items-center space-x-1">
                  <span>↪ BENIGN BRANCH</span>
                </div>
                {renderNodeCard("E4")}
              </div>
            </div>

            {/* AEGIS Blast Radius / Downstream Impact Boundary (E5 -> E6 -> E7) */}
            <div className="relative border-2 border-dashed border-red-300 bg-red-50/20 p-3 rounded-md flex space-x-10">
              <div className="absolute -top-3 left-4 bg-red-100 border border-red-300 text-red-900 font-mono text-[10px] font-bold px-2 py-0.5 rounded-xs tracking-wider uppercase flex items-center space-x-1">
                <span>💥 AEGIS IMPACT BOUNDARY (EXFILTRATION CHAIN)</span>
              </div>
              <div>{renderNodeCard("E5")}</div>
              <div>{renderNodeCard("E6")}</div>
              <div>{renderNodeCard("E7")}</div>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
};

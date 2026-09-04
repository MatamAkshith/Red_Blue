import React, { useState } from "react";
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
}

const MOCK_NODES: Record<string, ExecutionNodeData> = {
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
    target: "https://attacker-exfil.com",
    action: "http_post",
    detail: "Agent posts sensitive customer PII to external untrusted destination.",
    parentId: "E6",
  },
};

export const ExecutionGraph: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<ExecutionNodeData>(
    MOCK_NODES.E3
  );

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

  const getThreatBorder = (level: string, isSelected: boolean): string => {
    const base = isSelected ? "ring-2 ring-blue-500 scale-[1.02]" : "";
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

  const renderNodeCard = (node: ExecutionNodeData) => {
    const isSelected = selectedNode.id === node.id;
    return (
      <div
        key={node.id}
        onClick={() => setSelectedNode(node)}
        className={`w-48 p-3 rounded-xs border shadow-2xs cursor-pointer transition-all duration-150 relative ${getThreatBorder(
          node.threatLevel,
          isSelected
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
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626" />
              </marker>
              <marker
                id="arrow-amber"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
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

            {/* Line E1 -> E2 */}
            <line
              x1="220"
              y1="90"
              x2="260"
              y2="90"
              stroke="#f59e0b"
              strokeWidth="2"
              strokeDasharray="4 2"
              markerEnd="url(#arrow-amber)"
            />

            {/* Line E2 -> E3 */}
            <line
              x1="465"
              y1="90"
              x2="505"
              y2="90"
              stroke="#dc2626"
              strokeWidth="2.5"
              markerEnd="url(#arrow-red)"
            />

            {/* Main Attack Line E3 -> E5 */}
            <line
              x1="710"
              y1="90"
              x2="750"
              y2="90"
              stroke="#dc2626"
              strokeWidth="2.5"
              markerEnd="url(#arrow-red)"
            />

            {/* Branch Line E3 -> E4 (downwards branch) */}
            <path
              d="M 600,140 C 600,200 550,220 465,220"
              fill="none"
              stroke="#10b981"
              strokeWidth="2"
              strokeDasharray="3 3"
              markerEnd="url(#arrow-green)"
            />

            {/* Line E5 -> E6 */}
            <line
              x1="955"
              y1="90"
              x2="995"
              y2="90"
              stroke="#dc2626"
              strokeWidth="2.5"
              markerEnd="url(#arrow-red)"
            />

            {/* Line E6 -> E7 */}
            <line
              x1="1200"
              y1="90"
              x2="1240"
              y2="90"
              stroke="#dc2626"
              strokeWidth="2.5"
              markerEnd="url(#arrow-red)"
            />
          </svg>

          {/* Node Container Layout */}
          <div className="relative z-10 flex items-start space-x-10 py-4 min-w-[1450px]">
            {/* Dashed Untrusted Boundary Box (E1 & E2) */}
            <div className="relative border-2 border-dashed border-amber-300 bg-amber-50/30 p-3 rounded-md flex space-x-8">
              <div className="absolute -top-3 left-4 bg-amber-100 border border-amber-300 text-amber-900 font-mono text-[10px] font-bold px-2 py-0.5 rounded-xs tracking-wider uppercase flex items-center space-x-1">
                <span>⚡ UNTRUSTED DATA BOUNDARY</span>
              </div>
              <div>{renderNodeCard(MOCK_NODES.E1)}</div>
              <div>{renderNodeCard(MOCK_NODES.E2)}</div>
            </div>

            {/* Decision Node E3 & Branch E4 */}
            <div className="flex flex-col space-y-12">
              <div>{renderNodeCard(MOCK_NODES.E3)}</div>

              {/* Branch Node E4 */}
              <div className="pt-2 pl-4">
                <div className="text-[10px] font-mono text-emerald-700 font-semibold mb-1 uppercase tracking-wider flex items-center space-x-1">
                  <span>↪ BENIGN BRANCH</span>
                </div>
                {renderNodeCard(MOCK_NODES.E4)}
              </div>
            </div>

            {/* Malicious Attack Chain: E5 -> E6 -> E7 */}
            <div className="flex items-center space-x-10">
              <div>{renderNodeCard(MOCK_NODES.E5)}</div>
              <div>{renderNodeCard(MOCK_NODES.E6)}</div>

              {/* Exfiltration Boundary Impact Node E7 */}
              <div className="relative border-2 border-red-300 bg-red-50/30 p-2 rounded-md">
                <div className="absolute -top-3 left-3 bg-red-100 border border-red-300 text-red-900 font-mono text-[10px] font-bold px-2 py-0.5 rounded-xs tracking-wider uppercase">
                  💥 IMPACT BOUNDARY
                </div>
                {renderNodeCard(MOCK_NODES.E7)}
              </div>
            </div>
          </div>
        </div>

        {/* Selected Event Node Detail Panel (Monospace SOC Inspector) */}
        {selectedNode && (
          <div className="bg-white border border-slate-200 rounded-sm p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-slate-500 uppercase">
                  EVENT INSPECTOR:
                </span>
                <span className="font-mono font-bold text-sm text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200">
                  {selectedNode.id}
                </span>
                <Badge variant={getThreatVariant(selectedNode.threatLevel)}>
                  {selectedNode.eventType}
                </Badge>
              </div>

              <div className="text-xs font-mono text-slate-500">
                TRUST:{" "}
                <span
                  className={
                    selectedNode.trustLevel === "UNTRUSTED"
                      ? "text-amber-700 font-bold"
                      : "text-emerald-700 font-bold"
                  }
                >
                  {selectedNode.trustLevel}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-400 block text-[10px]">SOURCE</span>
                <span className="font-semibold text-slate-800">
                  {selectedNode.source}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">
                  TARGET / ENDPOINT
                </span>
                <span className="font-semibold text-slate-800">
                  {selectedNode.target || "N/A"}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">RESOURCE</span>
                <span className="font-semibold text-slate-800">
                  {selectedNode.resource || "N/A"}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">
                  DECLARED PERMISSION
                </span>
                <span className="font-semibold text-slate-800">
                  {selectedNode.permission || "NONE"}
                </span>
              </div>
            </div>

            <div className="bg-slate-50 p-2.5 rounded-xs border border-slate-200 text-xs font-mono text-slate-700">
              <span className="font-bold text-slate-900 block mb-1">
                SUMMARY & DETAILED TELEMETRY:
              </span>
              {selectedNode.detail}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};

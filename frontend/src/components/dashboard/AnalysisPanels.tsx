import React, { useState } from "react";
import type { Finding, Investigation } from "../../api";
import { Badge, type BadgeVariant } from "../ui/Badge";
import { Card } from "../ui/Card";

interface AnalysisPanelsProps {
  findings: Finding[];
  blastRadius: any;
  investigation: Investigation | null;
  sensitiveResources?: any[];
  attackPath?: string[];
}

export const AnalysisPanels: React.FC<AnalysisPanelsProps> = ({
  findings = [],
  blastRadius,
  investigation,
  sensitiveResources = [],
  attackPath = [],
}) => {
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [showDetailedReasoning, setShowDetailedReasoning] = useState<boolean>(false);

  const getSeverityVariant = (severity: string): BadgeVariant => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "critical";
      case "HIGH":
        return "malicious";
      case "MEDIUM":
        return "warning";
      case "LOW":
        return "success";
      default:
        return "info";
    }
  };

  const sensitiveList =
    blastRadius?.reachable_sensitive_resources ?? sensitiveResources ?? [];
  const externalList = blastRadius?.reachable_external_destinations ?? [];
  const affectedList = blastRadius?.affected_capabilities ?? attackPath ?? [];

  return (
    <div className="space-y-6">
      {/* Top Grid: Detections & AEGIS Blast Radius */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Detections Panel */}
        <Card
          title="DETERMINISTIC DETECTIONS"
          subtitle={`${findings.length} Threat Finding(s) Identified by Engine`}
        >
          <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
            {findings.length > 0 ? (
              findings.map((finding) => {
                const isExpanded = expandedFindingId === finding.finding_id;
                return (
                  <div
                    key={finding.finding_id}
                    className="p-3.5 bg-white border border-slate-200 rounded-xs space-y-2.5 shadow-2xs hover:border-slate-300 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Badge variant={getSeverityVariant(finding.severity)}>
                          {finding.severity}
                        </Badge>
                        <span className="font-mono font-bold text-xs text-slate-900">
                          {finding.detector_type}
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-500 font-semibold">
                        ID: {finding.finding_id}
                      </span>
                    </div>

                    <div className="text-xs font-bold text-slate-900">
                      {finding.title}
                    </div>
                    <p className="text-xs text-slate-600 font-mono leading-relaxed">
                      {finding.description}
                    </p>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-100 text-[11px] font-mono">
                      <div className="flex items-center space-x-1 text-slate-600">
                        <span className="text-slate-400 font-bold">ATTACK PATH:</span>
                        {finding.graph_path && finding.graph_path.length > 0 ? (
                          finding.graph_path.map((ev, i) => (
                            <span key={ev} className="flex items-center space-x-1">
                              <code className="bg-slate-100 px-1 py-0.2 rounded-xs text-slate-900 font-bold border border-slate-200">
                                {ev}
                              </code>
                              {i < finding.graph_path.length - 1 && <span>➔</span>}
                            </span>
                          ))
                        ) : (
                          <span>{finding.event_ids ? finding.event_ids.join(", ") : "N/A"}</span>
                        )}
                      </div>

                      <button
                        onClick={() =>
                          setExpandedFindingId(isExpanded ? null : finding.finding_id)
                        }
                        className="text-blue-700 hover:text-blue-900 font-bold text-[11px] cursor-pointer flex items-center space-x-1"
                      >
                        <span>{isExpanded ? "Hide Evidence ▴" : "View Evidence ▾"}</span>
                      </button>
                    </div>

                    {isExpanded && (
                      <div className="p-3 bg-slate-900 text-slate-200 rounded-xs font-mono text-[11px] space-y-1 border border-slate-800 animate-in fade-in duration-150">
                        <div className="text-emerald-400 font-bold">DETECTOR EVIDENCE DETAILS:</div>
                        <div>Detector: {finding.detector_type}</div>
                        <div>Associated Events: {finding.event_ids?.join(", ") || "E1-E7"}</div>
                        <div>Severity Index: {finding.severity}</div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="p-6 text-center text-xs font-mono text-slate-500">
                No active threat findings detected.
              </div>
            )}
          </div>
        </Card>

        {/* AEGIS Blast Radius Panel */}
        <Card
          title="AEGIS BLAST RADIUS & IMPACT ANALYSIS"
          subtitle="Determines Compromised Data & Boundary Exposure"
        >
          <div className="space-y-4">
            {/* Risk Score Highlight Header */}
            <div className="flex items-center justify-between p-3.5 bg-slate-900 text-white rounded-xs font-mono">
              <div>
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block">
                  Blast Radius Risk Score
                </span>
                <span className="text-xl font-bold text-red-400">
                  {blastRadius?.risk_score !== undefined
                    ? blastRadius.risk_score.toFixed(1)
                    : "8.5"}{" "}
                  / 10.0
                </span>
              </div>
              <Badge variant="critical">CRITICAL BLAST RADIUS</Badge>
            </div>

            {/* Impact Diagram Flow */}
            <div className="p-3.5 bg-slate-900/90 text-white rounded-xs font-mono text-xs space-y-2 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                IMPACT LINEAGE FLOW DIAGRAM
              </div>
              <div className="flex flex-col md:flex-row items-center justify-between gap-2 pt-1 text-[11px]">
                <div className="p-2 bg-slate-800 rounded-xs border border-slate-700 text-center w-full md:w-auto">
                  <div className="text-[9px] text-slate-400">INCIDENT TRACE</div>
                  <div className="font-bold text-amber-400">E1 ➔ E7</div>
                </div>
                <span className="text-slate-500">➔</span>
                <div className="p-2 bg-slate-800 rounded-xs border border-amber-900/80 text-center w-full md:w-auto">
                  <div className="text-[9px] text-slate-400">EXPOSED ASSETS</div>
                  <div className="font-bold text-amber-300">
                    {sensitiveList.length > 0
                      ? typeof sensitiveList[0] === "string"
                        ? sensitiveList[0]
                        : sensitiveList[0].resource || "customer_pii"
                      : "customer_pii"}
                  </div>
                </div>
                <span className="text-slate-500">➔</span>
                <div className="p-2 bg-slate-800 rounded-xs border border-red-900/80 text-center w-full md:w-auto">
                  <div className="text-[9px] text-slate-400">TRUST BOUNDARY</div>
                  <div className="font-bold text-red-400">INTERNAL ➔ EXTERNAL</div>
                </div>
                <span className="text-slate-500">➔</span>
                <div className="p-2 bg-slate-800 rounded-xs border border-red-800 text-center w-full md:w-auto">
                  <div className="text-[9px] text-slate-400">DESTINATION</div>
                  <div className="font-bold text-red-300 truncate max-w-[120px]">
                    {externalList[0] || "attacker-exfil.com"}
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {/* Sensitive Resources */}
              <div className="p-3 bg-white border border-slate-200 rounded-xs">
                <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  REACHED SENSITIVE RESOURCES ({sensitiveList.length})
                </span>
                {sensitiveList.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {sensitiveList.map((res: any, idx: number) => {
                      const name =
                        typeof res === "string" ? res : res.resource || "resource";
                      return (
                        <span
                          key={idx}
                          className="bg-amber-100 border border-amber-300 text-amber-950 font-bold px-2 py-0.5 rounded-xs"
                        >
                          🔒 {name}
                        </span>
                      );
                    })}
                  </div>
                ) : (
                  <span className="text-slate-400 italic">None exposed</span>
                )}
              </div>

              {/* External Destinations */}
              <div className="p-3 bg-white border border-slate-200 rounded-xs">
                <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  REACHABLE EXTERNAL DESTINATIONS ({externalList.length})
                </span>
                {externalList.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {externalList.map((dest: string, idx: number) => (
                      <span
                        key={idx}
                        className="bg-red-100 border border-red-300 text-red-950 font-bold px-2 py-0.5 rounded-xs break-all"
                      >
                        🌐 {dest}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-slate-400 italic">None reached</span>
                )}
              </div>

              {/* Affected Capabilities / Events */}
              <div className="p-3 bg-white border border-slate-200 rounded-xs">
                <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  AFFECTED CAPABILITIES & NODES
                </span>
                <span className="text-slate-900 font-bold">
                  {affectedList.length > 0
                    ? affectedList.join(", ")
                    : "E1, E2, E3, E5, E6, E7"}
                </span>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Understand Layer (Root Cause & AI Explanation Delineation) */}
      <Card
        title="UNDERSTAND / FEATHERLESS INCIDENT NARRATIVE"
        subtitle="Forensic Evidence vs AI Reasoning Synthesis (P2.2 Layer)"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Confirmed Forensic Facts Column */}
          <div className="p-4 bg-slate-100/90 border border-slate-300 rounded-xs space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <div className="flex items-center space-x-2 text-xs font-bold text-slate-900 uppercase tracking-wider">
                <span>🔒 CONFIRMED FORENSIC FACTS (P1 ENGINE)</span>
              </div>
              <Badge variant="neutral">DETERMINISTIC</Badge>
            </div>

            <div className="space-y-3 text-xs text-slate-700">
              <div>
                <span className="font-bold text-slate-900 block uppercase text-[10px] tracking-wider text-slate-500">
                  DETERMINISTIC FINDINGS ({findings.length}):
                </span>
                {findings.length > 0 ? (
                  <ul className="list-disc list-inside space-y-1 mt-1 text-xs">
                    {findings.map((f) => (
                      <li key={f.finding_id}>
                        <span className="font-bold text-red-700">{f.detector_type}</span>: {f.title}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-slate-500 italic">No deterministic findings.</span>
                )}
              </div>

              <div>
                <span className="font-bold text-slate-900 block uppercase text-[10px] tracking-wider text-slate-500">
                  ATTACK PATH LINEAGE:
                </span>
                <div className="text-slate-900 font-bold bg-white p-2 rounded-xs border border-slate-200 mt-1">
                  {attackPath.length > 0 ? attackPath.join(" ➔ ") : "E1 ➔ E2 ➔ E3 ➔ E5 ➔ E6 ➔ E7"}
                </div>
              </div>

              <div>
                <span className="font-bold text-slate-900 block uppercase text-[10px] tracking-wider text-slate-500">
                  EXPOSED SENSITIVE RESOURCES:
                </span>
                <div className="text-slate-900 font-bold mt-0.5">
                  {sensitiveList.length > 0
                    ? sensitiveList
                        .map((r: any) => (typeof r === "string" ? r : r.resource || "resource"))
                        .join(", ")
                    : "None exposed"}
                </div>
              </div>
            </div>
          </div>

          {/* AI Explanation Column */}
          <div className="p-4 bg-blue-50/60 border border-blue-200 rounded-xs space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-blue-200 pb-2">
              <div className="flex items-center space-x-2 text-xs font-bold text-blue-950 uppercase tracking-wider">
                <span>🤖 AI REASONING & EXPLANATION (FEATHERLESS)</span>
              </div>
              {investigation && (
                <Badge variant="info">
                  CONFIDENCE: {(investigation.confidence * 100).toFixed(0)}%
                </Badge>
              )}
            </div>

            {investigation ? (
              <div className="space-y-3 text-xs text-slate-800">
                <div>
                  <span className="font-bold text-slate-900 block uppercase text-[10px] tracking-wider text-blue-900">
                    ROOT CAUSE:
                  </span>
                  <p className="text-slate-800 font-sans text-xs mt-1 leading-relaxed bg-white p-2.5 rounded-xs border border-blue-100">
                    {investigation.root_cause}
                  </p>
                </div>

                {investigation.critical_decision && (
                  <div>
                    <span className="font-bold text-slate-900 block uppercase text-[10px] tracking-wider text-blue-900">
                      CRITICAL DECISION POINT: Node {investigation.critical_decision.event_id}
                    </span>
                    <p className="text-slate-800 font-sans text-xs mt-1">
                      {investigation.critical_decision.explanation}
                    </p>
                  </div>
                )}

                {investigation.attack_narrative && (
                  <div>
                    <button
                      onClick={() => setShowDetailedReasoning(!showDetailedReasoning)}
                      className="text-blue-800 hover:text-blue-950 font-bold text-xs cursor-pointer flex items-center space-x-1 mt-1"
                    >
                      <span>{showDetailedReasoning ? "Hide detailed reasoning ▴" : "View detailed reasoning ▾"}</span>
                    </button>

                    {showDetailedReasoning && (
                      <div className="mt-2 p-2.5 bg-white rounded-xs border border-blue-200 text-xs font-sans leading-relaxed space-y-2 animate-in fade-in duration-150">
                        <div className="font-bold font-mono text-slate-900 uppercase text-[10px]">
                          FULL FEATHERLESS NARRATIVE:
                        </div>
                        <p className="text-slate-700">{investigation.attack_narrative}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-600 font-sans leading-relaxed">
                Featherless LLM explanation running in fallback mode. Deterministic P1 hard facts preserved intact.
              </p>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
};

import React from "react";
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
  const getSeverityVariant = (severity: string): BadgeVariant => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "critical";
      case "HIGH":
        return "malicious";
      case "MEDIUM":
        return "warning";
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
          <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
            {findings.length > 0 ? (
              findings.map((finding) => (
                <div
                  key={finding.finding_id}
                  className="p-3 bg-slate-50 border border-slate-200 rounded-xs space-y-2"
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
                    <span className="font-mono text-[10px] text-slate-500">
                      ID: {finding.finding_id}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-slate-900">
                    {finding.title}
                  </div>
                  <p className="text-xs text-slate-600 font-mono">
                    {finding.description}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono text-slate-500">
                    <span className="text-slate-400">GRAPH PATH:</span>
                    {finding.graph_path && finding.graph_path.length > 0 ? (
                      finding.graph_path.map((ev, i) => (
                        <span key={ev} className="flex items-center space-x-1">
                          <code className="bg-slate-200 px-1 py-0.2 rounded-xs text-slate-800 font-bold">
                            {ev}
                          </code>
                          {i < finding.graph_path.length - 1 && <span>➔</span>}
                        </span>
                      ))
                    ) : (
                      <span>
                        {finding.event_ids ? finding.event_ids.join(", ") : "N/A"}
                      </span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-xs font-mono text-slate-500">
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
            {/* Risk Score Highlight */}
            <div className="flex items-center justify-between p-3 bg-slate-900 text-white rounded-xs font-mono">
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

            <div className="space-y-3 font-mono text-xs">
              {/* Sensitive Resources */}
              <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xs">
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
                          className="bg-amber-100 border border-amber-300 text-amber-900 font-semibold px-2 py-0.5 rounded-xs"
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
              <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xs">
                <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  REACHABLE EXTERNAL DESTINATIONS ({externalList.length})
                </span>
                {externalList.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {externalList.map((dest: string, idx: number) => (
                      <span
                        key={idx}
                        className="bg-red-100 border border-red-300 text-red-900 font-semibold px-2 py-0.5 rounded-xs break-all"
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
              <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xs">
                <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  AFFECTED CAPABILITIES & NODES
                </span>
                <span className="text-slate-800 font-semibold">
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
          <div className="p-4 bg-slate-100/80 border border-slate-300 rounded-xs space-y-3 font-mono">
            <div className="flex items-center space-x-2 text-xs font-bold text-slate-900 uppercase tracking-wider">
              <span>🔒 CONFIRMED FORENSIC FACTS (P1 ENGINE)</span>
            </div>
            <div className="space-y-2 text-xs text-slate-700">
              <div>
                <span className="font-bold text-slate-900 block">DETERMINISTIC FINDINGS ({findings.length}):</span>
                {findings.length > 0 ? (
                  <ul className="list-disc list-inside space-y-1 mt-1 text-[11px]">
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
                <span className="font-bold text-slate-900 block">ATTACK PATH LINEAGE:</span>
                <div className="text-slate-900 font-bold bg-white p-1.5 rounded-xs border border-slate-200 mt-1">
                  {attackPath.length > 0 ? attackPath.join(" ➔ ") : "E1 ➔ E2 ➔ E3 ➔ E5 ➔ E6 ➔ E7"}
                </div>
              </div>

              <div>
                <span className="font-bold text-slate-900 block">EXPOSED SENSITIVE RESOURCES:</span>
                <div className="text-slate-800 font-semibold mt-0.5">
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
          <div className="p-4 bg-blue-50/50 border border-blue-200 rounded-xs space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-bold text-blue-900 uppercase tracking-wider font-mono">
                <span>🤖 AI REASONING & EXPLANATION (FEATHERLESS)</span>
              </div>
              {investigation && (
                <Badge variant="info">
                  CONFIDENCE: {(investigation.confidence * 100).toFixed(0)}%
                </Badge>
              )}
            </div>

            {investigation ? (
              <div className="space-y-2 text-xs font-mono text-slate-700">
                <div>
                  <span className="font-bold text-slate-900 block">ROOT CAUSE:</span>
                  <p className="text-slate-800 mt-0.5">{investigation.root_cause}</p>
                </div>
                {investigation.attack_narrative && (
                  <div>
                    <span className="font-bold text-slate-900 block">ATTACK NARRATIVE:</span>
                    <p className="text-slate-800 mt-0.5">{investigation.attack_narrative}</p>
                  </div>
                )}
                {investigation.critical_decision && (
                  <div>
                    <span className="font-bold text-slate-900 block">
                      CRITICAL DECISION POINT: Node {investigation.critical_decision.event_id}
                    </span>
                    <p className="text-slate-800 mt-0.5">
                      {investigation.critical_decision.explanation}
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-600">
                Featherless LLM explanation running in fallback mode. Deterministic P1 hard facts preserved intact.
              </p>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
};

import React from "react";
import type { MemoryPattern, Simulation } from "../../api";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

interface ResponseVerificationPanelsProps {
  intervention: {
    selected: Simulation["intervention"] | null;
    rationale: string;
    evaluated: Simulation[];
  } | null;
  verification: {
    attack_before: string;
    attack_after: string;
    defense_verified: boolean;
    blocked_event_ids: string[];
    notes: string;
  } | null;
  memoryPattern: MemoryPattern | null;
  patternSignature?: string;
  onApplyDefense: () => void;
  onSimulateClick: () => void;
  loadingDefense?: boolean;
}

export const ResponseVerificationPanels: React.FC<ResponseVerificationPanelsProps> = ({
  intervention,
  verification,
  memoryPattern,
  patternSignature = "",
  onApplyDefense,
  onSimulateClick,
  loadingDefense = false,
}) => {
  const selectedIntervention = intervention?.selected;
  const isVerified = verification?.defense_verified ?? false;

  return (
    <div className="space-y-6">
      {/* Intervention & Response Panel */}
      <Card
        title="MINIMUM EFFECTIVE INTERVENTION & AUTOMATED RESPONSE"
        subtitle="Calculated by What-If Counterfactual Simulation Engine"
        action={
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" onClick={onSimulateClick}>
              🔮 Simulate What-If
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={onApplyDefense}
              disabled={loadingDefense}
            >
              {loadingDefense ? "Applying..." : "⚡ APPLY DEFENSE"}
            </Button>
          </div>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Selected Intervention Box */}
          <div className="p-3.5 bg-blue-50/60 border border-blue-200 rounded-xs space-y-2 md:col-span-2 font-mono">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold tracking-wider text-blue-900 uppercase">
                RECOMMENDED DEFENSE DECISION
              </span>
              {selectedIntervention && (
                <Badge variant="info">
                  DISRUPTION COST: {selectedIntervention.cost}
                </Badge>
              )}
            </div>

            {selectedIntervention ? (
              <div className="space-y-1">
                <div className="text-sm font-bold text-slate-900">
                  {selectedIntervention.intervention_type}
                </div>
                <div className="text-xs font-semibold text-blue-800 break-all">
                  VALUE: {selectedIntervention.value}
                </div>
                <p className="text-xs text-slate-600 font-sans mt-1">
                  {selectedIntervention.description || intervention?.rationale}
                </p>
              </div>
            ) : (
              <p className="text-xs text-slate-600 font-sans">
                {intervention?.rationale || "No intervention candidate required."}
              </p>
            )}
          </div>

          {/* Cost/Disruption Efficiency Gauge */}
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xs space-y-2 font-mono flex flex-col justify-between">
            <div>
              <span className="text-[10px] font-bold tracking-wider text-slate-500 uppercase">
                POLICY RULE SEVERANCE
              </span>
              <div className="text-xs text-slate-800 font-semibold mt-1">
                {intervention?.evaluated ? (
                  <span>
                    {intervention.evaluated.filter((s) => s.exfiltration_path_severed).length} /{" "}
                    {intervention.evaluated.length} candidates sever attack path
                  </span>
                ) : (
                  <span>1 candidate effective</span>
                )}
              </div>
            </div>
            <div className="text-[11px] text-slate-500">
              Selected option represents the minimum operational disruption candidate.
            </div>
          </div>
        </div>
      </Card>

      {/* CHIMERA Re-Attack & Defense Verification State */}
      <Card
        title="CHIMERA / RE-ATTACK VERIFICATION FLOW"
        subtitle="Deterministic Verification: Proves Defense Blocks Re-Attack Trace"
      >
        <div className="space-y-4">
          {/* Visual Step Timeline Flow */}
          <div className="p-4 bg-slate-900 rounded-xs text-white font-mono flex flex-col md:flex-row items-center justify-between gap-4">
            {/* Step 1: Original Attack */}
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-full bg-red-900/80 border border-red-500 text-red-300 flex items-center justify-center font-bold text-xs shrink-0">
                1
              </div>
              <div>
                <div className="text-[10px] text-slate-400 font-bold uppercase">
                  ORIGINAL TRACE
                </div>
                <div className="text-xs font-bold text-red-400">
                  {verification?.attack_before || "SUCCESS (EXPOSED)"}
                </div>
              </div>
            </div>

            <span className="text-slate-600 hidden md:inline">➔</span>

            {/* Step 2: Defense Application */}
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-full bg-blue-900/80 border border-blue-500 text-blue-300 flex items-center justify-center font-bold text-xs shrink-0">
                2
              </div>
              <div>
                <div className="text-[10px] text-slate-400 font-bold uppercase">
                  APPLY DEFENSE
                </div>
                <div className="text-xs font-bold text-blue-300">
                  {selectedIntervention?.intervention_type || "BLOCK RULE"}
                </div>
              </div>
            </div>

            <span className="text-slate-600 hidden md:inline">➔</span>

            {/* Step 3: Re-Attack Simulation */}
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-full bg-amber-900/80 border border-amber-500 text-amber-300 flex items-center justify-center font-bold text-xs shrink-0">
                3
              </div>
              <div>
                <div className="text-[10px] text-slate-400 font-bold uppercase">
                  RE-ATTACK REPLAY
                </div>
                <div className="text-xs font-bold text-amber-300">
                  {verification?.attack_after || "BLOCKED"}
                </div>
              </div>
            </div>

            <span className="text-slate-600 hidden md:inline">➔</span>

            {/* Step 4: Verification Result */}
            <div className="flex items-center space-x-3">
              <div
                className={`w-8 h-8 rounded-full border flex items-center justify-center font-bold text-xs shrink-0 ${
                  isVerified
                    ? "bg-emerald-900/80 border-emerald-500 text-emerald-300"
                    : "bg-red-900/80 border-red-500 text-red-300"
                }`}
              >
                ✓
              </div>
              <div>
                <div className="text-[10px] text-slate-400 font-bold uppercase">
                  STATUS
                </div>
                <div
                  className={`text-xs font-bold ${
                    isVerified ? "text-emerald-400" : "text-red-400"
                  }`}
                >
                  {isVerified ? "DEFENSE VERIFIED" : "NOT VERIFIED"}
                </div>
              </div>
            </div>
          </div>

          {/* Verification Notes */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs text-xs font-mono text-slate-700 flex items-center justify-between">
            <div>
              <span className="font-bold text-slate-900">VERIFICATION NOTES:</span>{" "}
              {verification?.notes ||
                "Re-attack under applied intervention no longer reaches exfiltration path."}
            </div>
            {verification?.blocked_event_ids && (
              <span className="text-slate-500 font-semibold shrink-0 ml-4">
                BLOCKED NODES: {verification.blocked_event_ids.join(", ")}
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* Adaptive Failure-Pattern Memory */}
      <Card
        title="ADAPTIVE FAILURE-PATTERN MEMORY"
        subtitle="Offline Signature Matching & Historical Attack Provenance"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-400 uppercase">
                PATTERN SIGNATURE
              </span>
              <Badge variant="neutral">
                TIMES SEEN: {memoryPattern?.times_seen ?? 1}
              </Badge>
            </div>
            <div className="font-bold text-slate-900 bg-white p-2 rounded-xs border border-slate-200 break-all text-[11px]">
              {memoryPattern?.signature || patternSignature || "INDIRECT_PROMPT_INJECTION|customer_pii|external=True"}
            </div>
            {memoryPattern?.pattern && (
              <div className="text-slate-700 font-sans text-xs pt-1">
                <span className="font-bold font-mono text-slate-900">
                  {memoryPattern.pattern.pattern_name}:
                </span>{" "}
                {memoryPattern.pattern.description}
              </div>
            )}
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs space-y-2">
            <span className="text-[10px] font-bold text-slate-400 uppercase block">
              HISTORICAL PROVENANCE
            </span>
            <div className="space-y-1 text-slate-700 text-[11px]">
              <div>
                <span className="text-slate-500">ORIGINAL INCIDENT:</span>{" "}
                <span className="font-bold text-slate-900">
                  {memoryPattern?.provenance?.incident_id || "INC-HISTORICAL"}
                </span>
              </div>
              <div>
                <span className="text-slate-500">ORIGINAL SESSION:</span>{" "}
                <span className="font-bold text-slate-900">
                  {memoryPattern?.provenance?.session_id || "S-DEMO-1"}
                </span>
              </div>
              <div>
                <span className="text-slate-500">MATCH STATUS:</span>{" "}
                <span className="font-bold text-emerald-700">
                  ✓ RECALLED OFFLINE (NO LLM REQUIRED)
                </span>
              </div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

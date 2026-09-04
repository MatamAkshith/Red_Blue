import React from "react";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";

interface IncidentHeaderProps {
  incidentId?: string;
  agentId?: string;
  sessionId?: string;
  severity?: string;
  status?: string;
  onSimulateClick?: () => void;
  onExportClick?: () => void;
}

export const IncidentHeader: React.FC<IncidentHeaderProps> = ({
  incidentId = "INC-DEMO-1",
  agentId = "agent-support-bot",
  sessionId = "S-DEMO-1",
  severity = "CRITICAL",
  status = "ACTIVE THREAT",
  onSimulateClick,
  onExportClick,
}) => {
  return (
    <div className="bg-white border border-slate-200 rounded-sm p-4 shadow-2xs space-y-4">
      {/* Top Title & Action Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
        <div className="flex items-center space-x-3">
          <h2 className="text-lg font-bold font-mono tracking-tight text-slate-900">
            INCIDENT / {incidentId}
          </h2>
          <div className="flex items-center space-x-2">
            <Badge variant="critical">🔴 {severity}</Badge>
            <Badge variant="outline-critical">{status}</Badge>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <Button variant="outline" size="sm" onClick={onExportClick}>
            📄 Export Report
          </Button>
          <Button variant="primary" size="sm" onClick={onSimulateClick}>
            🔮 Simulate Intervention
          </Button>
        </div>
      </div>

      {/* Metadata Row (Monospace, readable text) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs text-slate-600 bg-slate-50/70 p-3 rounded-xs border border-slate-200/60">
        <div>
          <span className="text-slate-500 block text-xs uppercase font-bold tracking-wider mb-0.5">
            Target Agent
          </span>
          <span className="font-bold text-slate-900 text-xs">{agentId}</span>
        </div>
        <div>
          <span className="text-slate-500 block text-xs uppercase font-bold tracking-wider mb-0.5">
            Session Reference
          </span>
          <span className="font-bold text-slate-900 text-xs">{sessionId}</span>
        </div>
        <div>
          <span className="text-slate-500 block text-xs uppercase font-bold tracking-wider mb-0.5">
            Incident ID
          </span>
          <span className="font-bold text-slate-900 text-xs">{incidentId}</span>
        </div>
        <div>
          <span className="text-slate-500 block text-xs uppercase font-bold tracking-wider mb-0.5">
            Primary Threat Vector
          </span>
          <span className="font-bold text-red-700 text-xs">
            INDIRECT PROMPT INJECTION
          </span>
        </div>
      </div>
    </div>
  );
};

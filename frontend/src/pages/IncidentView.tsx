import React from "react";
import { IncidentHeader } from "../components/dashboard/IncidentHeader";
import { ExecutionGraph } from "../components/dashboard/ExecutionGraph";
import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";

export const IncidentView: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Step 3: Incident Header */}
      <IncidentHeader
        incidentId="INC-DEMO-1"
        agentId="agent-support-bot"
        sessionId="S-DEMO-1"
        severity="CRITICAL"
        status="ACTIVE THREAT"
        onSimulateClick={() => alert("Simulating Intervention What-If analysis...")}
        onExportClick={() => alert("Exporting Incident Report PDF/JSON...")}
      />

      {/* Summary KPI Highlights Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Total Telemetry Events
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 mt-1">7</div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
            Trace Lineage (E1 ➔ E7)
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Attack Path Length
          </div>
          <div className="text-2xl font-bold font-mono text-red-600 mt-1">
            6 <span className="text-xs text-slate-400 font-normal">nodes</span>
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
            Primary Kill Chain
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Sensitive Resources
          </div>
          <div className="text-2xl font-bold font-mono text-amber-600 mt-1">1</div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5 truncate">
            customer_pii
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Exfiltration Endpoints
          </div>
          <div className="text-2xl font-bold font-mono text-red-600 mt-1">1</div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5 truncate">
            attacker-exfil.com
          </div>
        </Card>
      </div>

      {/* Step 4: Execution Graph Component */}
      <ExecutionGraph />

      {/* Quick Status / Findings Preview Box */}
      <Card title="DETECTOR FINDINGS SUMMARY">
        <div className="space-y-3">
          <div className="flex items-start justify-between p-3 bg-red-50/60 border border-red-200 rounded-xs">
            <div>
              <div className="flex items-center space-x-2">
                <Badge variant="malicious">INDIRECT_PROMPT_INJECTION</Badge>
                <span className="font-semibold text-xs text-slate-900">
                  Untrusted Context Instruction Hijack
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1 font-mono">
                Event E2 retrieved untrusted document payload that overrode decision node E3 into unauthorized CRM export.
              </p>
            </div>
            <span className="text-xs font-mono font-bold text-red-700">HIGH CONFIDENCE</span>
          </div>

          <div className="flex items-start justify-between p-3 bg-red-50/60 border border-red-200 rounded-xs">
            <div>
              <div className="flex items-center space-x-2">
                <Badge variant="malicious">DATA_EXFILTRATION</Badge>
                <span className="font-semibold text-xs text-slate-900">
                  Sensitive PII Transmission to External Host
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1 font-mono">
                Directed path from customer_pii access (E5) to untrusted external HTTP destination (E7).
              </p>
            </div>
            <span className="text-xs font-mono font-bold text-red-700">CRITICAL</span>
          </div>
        </div>
      </Card>
    </div>
  );
};

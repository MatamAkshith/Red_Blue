import React, { useEffect, useState } from "react";
import type {
  AgentEvent,
  IncidentResponse,
  SensitiveResource,
} from "../api";
import {
  analyzeIncident,
  defendIncident,
  fetchDemoScenario,
  simulateIntervention,
} from "../api";
import { AnalysisPanels } from "../components/dashboard/AnalysisPanels";
import { EventInspectorDrawer } from "../components/dashboard/EventInspectorDrawer";
import { ExecutionGraph } from "../components/dashboard/ExecutionGraph";
import { IncidentHeader } from "../components/dashboard/IncidentHeader";
import { ResponseVerificationPanels } from "../components/dashboard/ResponseVerificationPanels";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";

export const IncidentView: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingDefense, setLoadingDefense] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [rawEvents, setRawEvents] = useState<AgentEvent[]>([]);
  const [, setKnownResources] = useState<SensitiveResource[]>([]);
  const [response, setResponse] = useState<IncidentResponse | null>(null);

  const [selectedEvent, setSelectedEvent] = useState<AgentEvent | null>(null);

  // Load initial demo scenario and analyze over backend API
  const loadData = async (withExplain: boolean = true) => {
    setLoading(true);
    setError(null);
    try {
      const scenario = await fetchDemoScenario();
      setRawEvents(scenario.events);
      setKnownResources(scenario.known_sensitive_resources);

      const res = await analyzeIncident(
        scenario.events,
        scenario.known_sensitive_resources,
        withExplain,
        "INC-DEMO-1"
      );
      setResponse(res);
      if (res.events && res.events.length > 0) {
        setSelectedEvent(res.events.find((e) => e.event_id === "E3") || res.events[0]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load incident data from backend API.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, []);

  const handleApplyDefense = async () => {
    if (!rawEvents.length) return;
    setLoadingDefense(true);
    try {
      const incidentId = response?.incident_info?.incident_id || "INC-DEMO-1";
      const verifResult = await defendIncident(incidentId, rawEvents);

      if (response) {
        setResponse({
          ...response,
          chimera_verification: {
            attack_before: verifResult.attack_before,
            attack_after: verifResult.attack_after,
            defense_verified: verifResult.defense_verified,
            blocked_event_ids: verifResult.blocked_event_ids,
            notes: "Defense successfully applied over CHIMERA verification framework.",
          },
          verification: {
            attack_before: verifResult.attack_before,
            attack_after: verifResult.attack_after,
            defense_verified: verifResult.defense_verified,
            blocked_event_ids: verifResult.blocked_event_ids,
            notes: "Defense successfully applied over CHIMERA verification framework.",
          },
          defense_result: {
            defense_verified: verifResult.defense_verified,
            attack_before: verifResult.attack_before,
            attack_after: verifResult.attack_after,
            blocked_events: verifResult.blocked_event_ids,
          },
        });
      }
    } catch (err: any) {
      alert(`Failed to apply defense: ${err.message}`);
    } finally {
      setLoadingDefense(false);
    }
  };

  const handleSimulateWhatIf = async () => {
    if (!rawEvents.length) return;
    try {
      const incidentId = response?.incident_info?.incident_id || "INC-DEMO-1";
      const simResult = await simulateIntervention(incidentId, rawEvents);
      alert(
        `What-If Simulation Status: ${simResult.status}\nEvaluated Candidates: ${simResult.evaluated_simulations.length}\nSelected Option: ${simResult.selected_intervention?.description}`
      );
    } catch (err: any) {
      alert(`Simulation error: ${err.message}`);
    }
  };

  if (loading && !response) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-white border border-slate-200 rounded-sm font-mono space-y-3">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        <div className="text-xs text-slate-600 font-bold uppercase tracking-wider">
          Connecting to BLACKBOX Backend Pipeline...
        </div>
      </div>
    );
  }

  const incidentInfo = response?.incident_info || response?.incident;
  const attackPath = response?.attack_path || response?.incident?.attack_path || [];
  const findings = response?.findings || [];
  const investigation = response?.investigation || null;
  const blastRadius = response?.blast_radius || response?.incident?.blast_radius;
  const intervention = response?.intervention || null;
  const verification = response?.chimera_verification || response?.verification || null;
  const memoryPattern = response?.memory_pattern || response?.recalled_pattern || null;

  return (
    <div className="space-y-6 relative">
      {/* Backend API Error Banner */}
      {error && (
        <div className="p-4 bg-red-50 border border-red-300 rounded-xs text-xs font-mono text-red-800 flex items-center justify-between">
          <div>
            <span className="font-bold">BACKEND COMMUNICATION ERROR:</span> {error}
          </div>
          <button
            onClick={() => loadData(true)}
            className="px-2 py-1 bg-red-800 text-white rounded-xs text-[10px] font-bold uppercase"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Incident Header */}
      <IncidentHeader
        incidentId={incidentInfo?.incident_id || "INC-DEMO-1"}
        agentId={incidentInfo?.agent_id || "agent-support-bot"}
        sessionId={incidentInfo?.session_id || "S-DEMO-1"}
        severity={incidentInfo?.severity || "CRITICAL"}
        status={
          verification?.defense_verified ? "DEFENSE VERIFIED" : "ACTIVE THREAT"
        }
        onSimulateClick={handleSimulateWhatIf}
        onExportClick={() =>
          alert(
            `Exporting full JSON payload for Incident ${
              incidentInfo?.incident_id || "INC-DEMO-1"
            }`
          )
        }
      />

      {/* Summary KPI Highlights Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Telemetry Events Analyzed
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 mt-1">
            {response?.events?.length || rawEvents.length || 7}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
            Trace Lineage (E1 ➔ E7)
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Attack Path Length
          </div>
          <div className="text-2xl font-bold font-mono text-red-600 mt-1">
            {attackPath.length}{" "}
            <span className="text-xs text-slate-400 font-normal">nodes</span>
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
            {attackPath.join(" ➔ ") || "E1 ➔ E2 ➔ E3 ➔ E5 ➔ E6 ➔ E7"}
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Sensitive Resources Exposed
          </div>
          <div className="text-2xl font-bold font-mono text-amber-600 mt-1">
            {blastRadius?.reachable_sensitive_resources?.length || 1}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-0.5 truncate">
            customer_pii
          </div>
        </Card>

        <Card className="bg-white">
          <div className="text-slate-500 font-mono text-[10px] uppercase font-bold tracking-wider">
            Verification Status
          </div>
          <div className="mt-1">
            <Badge
              variant={
                verification?.defense_verified ? "success" : "critical"
              }
            >
              {verification?.defense_verified ? "VERIFIED" : "UNVERIFIED"}
            </Badge>
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-1.5">
            CHIMERA Re-attack Replay
          </div>
        </Card>
      </div>

      {/* Execution Graph Component */}
      <ExecutionGraph
        events={response?.events || rawEvents}
        attackPath={attackPath}
        selectedEvent={selectedEvent}
        onNodeSelect={(ev) => setSelectedEvent(ev)}
      />

      {/* Analysis Panels (F3 Detections, AEGIS, Understand Narrative) */}
      <AnalysisPanels
        findings={findings}
        blastRadius={blastRadius}
        investigation={investigation}
        attackPath={attackPath}
      />

      {/* Response & Verification Panels (F4 Intervention, CHIMERA, Memory) */}
      <ResponseVerificationPanels
        intervention={intervention}
        verification={verification}
        memoryPattern={memoryPattern}
        patternSignature={response?.pattern_signature}
        onApplyDefense={handleApplyDefense}
        onSimulateClick={handleSimulateWhatIf}
        loadingDefense={loadingDefense}
      />

      {/* Step 1 Event Inspector Sidebar Drawer */}
      <EventInspectorDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
};

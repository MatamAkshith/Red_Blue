import React, { useState } from "react";
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
  const [isIdle, setIsIdle] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingDefense, setLoadingDefense] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [rawEvents, setRawEvents] = useState<AgentEvent[]>([]);
  const [, setKnownResources] = useState<SensitiveResource[]>([]);
  const [response, setResponse] = useState<IncidentResponse | null>(null);

  const [selectedEvent, setSelectedEvent] = useState<AgentEvent | null>(null);

  // Load demo scenario and analyze over backend API
  const loadData = async (withExplain: boolean = true) => {
    setIsIdle(false);
    setLoading(true);
    setError(null);
    setResponse(null);
    setRawEvents([]);
    setSelectedEvent(null);
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
      setError(err.message || "ERROR: Connection to BLACKBOX Core lost. Ensure backend FastAPI server is active.");
    } finally {
      setLoading(false);
    }
  };

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
            notes: `Defense verified via CHIMERA engine. Status: ${verifResult.status || "DEFENSE_VERIFIED"}`,
          },
          verification: {
            attack_before: verifResult.attack_before,
            attack_after: verifResult.attack_after,
            defense_verified: verifResult.defense_verified,
            blocked_event_ids: verifResult.blocked_event_ids,
            notes: `Defense verified via CHIMERA engine. Status: ${verifResult.status || "DEFENSE_VERIFIED"}`,
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
      if (response && simResult.selected_intervention) {
        setResponse({
          ...response,
          intervention: {
            selected: simResult.selected_intervention,
            rationale: `What-If simulation evaluated ${simResult.evaluated_simulations.length} candidate interventions. Selected minimum operational cost candidate.`,
            evaluated: simResult.evaluated_simulations,
          },
          what_if_result: simResult.selected_intervention as any,
        });
      }
      alert(
        `[WHAT-IF SIMULATION COMPLETE]\nStatus: ${simResult.status}\nEvaluated Candidates: ${simResult.evaluated_simulations.length}\nSelected Intervention: ${simResult.selected_intervention?.description}`
      );
    } catch (err: any) {
      alert(`Simulation error: ${err.message}`);
    }
  };

  // STEP 1: System Idle State Before Demo Attack Run
  if (isIdle && !loading && !response) {
    return (
      <div className="space-y-6 max-w-4xl mx-auto py-8">
        <div className="bg-white border border-slate-200 rounded-sm p-8 shadow-sm space-y-6 text-center">
          <div className="inline-flex items-center space-x-2 px-3 py-1 bg-blue-50 border border-blue-200 rounded-full font-mono text-xs text-blue-700 font-semibold">
            <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping" />
            <span>BLACKBOX AGENT OPERATIONAL CENTER</span>
          </div>

          <div className="space-y-2">
            <h1 className="text-2xl font-bold font-mono tracking-tight text-slate-900">
              SYSTEM STANDBY — DEMO SCENARIO READY
            </h1>
            <p className="text-sm font-sans text-slate-600 max-w-xl mx-auto">
              Simulate an Indirect Prompt Injection attack on the Customer Support Agent, observe the real-time execution graph, compute the AEGIS blast radius, and execute the CHIMERA counterfactual defense verification.
            </p>
          </div>

          {/* Prominent Primary Demo Trigger Button */}
          <div className="pt-4 flex flex-col items-center justify-center space-y-3">
            <button
              onClick={() => loadData(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white font-mono text-sm font-bold px-8 py-4 rounded-xs tracking-wider shadow-md flex items-center space-x-3 transition-all duration-200 cursor-pointer transform hover:-translate-y-0.5"
            >
              <span>▶</span>
              <span>RUN DEMO ATTACK</span>
            </button>
            <span className="text-[11px] font-mono text-slate-400">
              Triggers: GET /incidents/demo-scenario ➔ POST /incidents/analyze
            </span>
          </div>

          <div className="grid grid-cols-3 gap-4 pt-6 border-t border-slate-100 font-mono text-xs text-left">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs">
              <span className="text-[10px] text-slate-500 font-bold uppercase block mb-1">
                ATTACK VECTOR
              </span>
              <span className="font-semibold text-slate-900">Indirect Prompt Injection</span>
            </div>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs">
              <span className="text-[10px] text-slate-500 font-bold uppercase block mb-1">
                TARGET ASSET
              </span>
              <span className="font-semibold text-slate-900">CRM Customer PII Database</span>
            </div>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xs">
              <span className="text-[10px] text-slate-500 font-bold uppercase block mb-1">
                VERIFICATION ENGINE
              </span>
              <span className="font-semibold text-slate-900">CHIMERA Counterfactual</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // STEP 2: Loading State with Technical Telemetry Terminal
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] p-12 bg-white border border-slate-200 rounded-sm font-mono space-y-6 shadow-2xs">
        <div className="relative">
          <div className="w-12 h-12 rounded-full border-2 border-slate-200 border-t-blue-600 animate-spin" />
        </div>

        <div className="space-y-2 text-center">
          <div className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center justify-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse" />
            <span>Processing Graph Telemetry & Running Analysis...</span>
          </div>
          <div className="text-xs text-slate-500 max-w-md font-sans">
            Executing Task 4 backend pipeline over raw telemetry stream.
          </div>
        </div>

        {/* Technical Log Stream Skeleton */}
        <div className="w-full max-w-xl p-4 bg-slate-900 rounded-xs text-slate-300 font-mono text-[11px] space-y-1.5 border border-slate-800">
          <div className="text-emerald-400 font-bold">▶ GET /incidents/demo-scenario (200 OK)</div>
          <div className="text-slate-400">├── Ingesting raw events: E1 ➔ E2 ➔ E3 ➔ E4 ➔ E5 ➔ E6 ➔ E7</div>
          <div className="text-slate-400">├── Executing deterministic detection rules...</div>
          <div className="text-amber-400">├── Evaluating AEGIS blast radius & sensitive resources...</div>
          <div className="text-blue-400">└── Synthesizing P2.2 investigation narrative (Featherless / Fallback)...</div>
        </div>
      </div>
    );
  }

  // STEP 2: Technical Error State Boundary
  if (error) {
    return (
      <div className="p-8 bg-red-50 border border-red-300 rounded-sm font-mono space-y-4 max-w-3xl mx-auto shadow-sm">
        <div className="flex items-center space-x-3 text-red-900 font-bold text-base">
          <span className="px-2 py-0.5 bg-red-800 text-white rounded-xs text-xs">CRITICAL ERROR</span>
          <span>ERROR: Connection to BLACKBOX Core lost</span>
        </div>
        <p className="text-xs text-red-800 font-sans leading-relaxed">
          {error}
        </p>
        <div className="pt-2 flex items-center space-x-3">
          <button
            onClick={() => loadData(true)}
            className="px-4 py-2 bg-red-800 hover:bg-red-900 text-white font-mono text-xs font-bold rounded-xs transition-all duration-150 cursor-pointer"
          >
            ↻ RETRY CONNECTION
          </button>
          <button
            onClick={() => setIsIdle(true)}
            className="px-4 py-2 bg-white border border-red-300 text-red-900 hover:bg-red-100 font-mono text-xs font-bold rounded-xs transition-all duration-150 cursor-pointer"
          >
            ↩ RETURN TO STANDBY
          </button>
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
      {/* Top Demo Toolbar Bar */}
      <div className="flex items-center justify-between p-3 bg-slate-900 text-white rounded-xs font-mono text-xs">
        <div className="flex items-center space-x-3">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-bold text-slate-200">BLACKBOX LIVE SCENARIO</span>
          <span className="text-slate-400">|</span>
          <span className="text-slate-300 text-[11px]">INCIDENT: {incidentInfo?.incident_id || "INC-DEMO-1"}</span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => loadData(true)}
            disabled={loading}
            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xs text-[11px] font-bold tracking-wider transition-all duration-150 cursor-pointer flex items-center space-x-1"
          >
            <span>▶ RE-RUN DEMO ATTACK</span>
          </button>
          <button
            onClick={() => setIsIdle(true)}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xs text-[11px] font-bold tracking-wider transition-all duration-150 cursor-pointer"
          >
            ↩ RESET TO IDLE
          </button>
        </div>
      </div>

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
        <Card className="bg-white hover:border-slate-300 transition-all duration-200">
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

        <Card className="bg-white hover:border-slate-300 transition-all duration-200">
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

        <Card className="bg-white hover:border-slate-300 transition-all duration-200">
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

        <Card className="bg-white hover:border-slate-300 transition-all duration-200">
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


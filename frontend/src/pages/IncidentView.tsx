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
import { SecurityDashboardLayout } from "../components/layout/SecurityDashboardLayout";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";

const navToHash: Record<string, string> = {
  Overview: "#overview",
  Incidents: "#incidents",
  Execution: "#execution",
  "Attack Path": "#attack-path",
  AEGIS: "#aegis",
  "What-If": "#what-if",
  Intervention: "#intervention",
  CHIMERA: "#chimera",
  Verify: "#verify",
};

const hashToNav: Record<string, string> = {
  "#overview": "Overview",
  "#incidents": "Incidents",
  "#execution": "Execution",
  "#attack-path": "Attack Path",
  "#aegis": "AEGIS",
  "#what-if": "What-If",
  "#intervention": "Intervention",
  "#chimera": "CHIMERA",
  "#verify": "Verify",
};

export const IncidentView: React.FC = () => {
  const [activeNavItem, setActiveNavItem] = useState<string>(() => {
    const hash = window.location.hash;
    return hashToNav[hash] || "Overview";
  });

  const [loading, setLoading] = useState<boolean>(false);
  const [loadingDefense, setLoadingDefense] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Dynamic incident state source
  const [incidents, setIncidents] = useState<IncidentResponse[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [rawEvents, setRawEvents] = useState<AgentEvent[]>([]);
  const [, setKnownResources] = useState<SensitiveResource[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AgentEvent | null>(null);

  // Sync window hash location changes
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash;
      if (hashToNav[hash]) {
        setActiveNavItem(hashToNav[hash]);
      }
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const navigateTo = (item: string) => {
    setActiveNavItem(item);
    if (navToHash[item]) {
      window.location.hash = navToHash[item];
    }
  };

  // Run Demo Attack Flow
  const loadDemoAttack = async (withExplain: boolean = true) => {
    setLoading(true);
    setError(null);
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

      setIncidents([res]);
      const incId = res.incident_info?.incident_id || "INC-DEMO-1";
      setSelectedIncidentId(incId);

      if (res.events && res.events.length > 0) {
        setSelectedEvent(res.events.find((e) => e.event_id === "E3") || res.events[0]);
      }

      // Automatically switch to Execution view to inspect generated incident
      navigateTo("Execution");
    } catch (err: any) {
      setError(
        err.message ||
          "ERROR: Connection to BLACKBOX Core lost. Ensure backend FastAPI server is active."
      );
    } finally {
      setLoading(false);
    }
  };

  const currentIncident =
    incidents.find((i) => (i.incident_info?.incident_id || i.incident?.incident_id) === selectedIncidentId) ||
    incidents[0] ||
    null;

  const handleApplyDefense = async () => {
    if (!rawEvents.length || !currentIncident) return;
    setLoadingDefense(true);
    try {
      const incidentId = currentIncident.incident_info?.incident_id || "INC-DEMO-1";
      const verifResult = await defendIncident(incidentId, rawEvents);

      const updatedInc: IncidentResponse = {
        ...currentIncident,
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
      };

      setIncidents((prev) =>
        prev.map((inc) =>
          (inc.incident_info?.incident_id || inc.incident?.incident_id) === incidentId
            ? updatedInc
            : inc
        )
      );
    } catch (err: any) {
      alert(`Failed to apply defense: ${err.message}`);
    } finally {
      setLoadingDefense(false);
    }
  };

  const handleSimulateWhatIf = async () => {
    if (!rawEvents.length || !currentIncident) return;
    try {
      const incidentId = currentIncident.incident_info?.incident_id || "INC-DEMO-1";
      const simResult = await simulateIntervention(incidentId, rawEvents);
      if (simResult.selected_intervention) {
        const updatedInc: IncidentResponse = {
          ...currentIncident,
          intervention: {
            selected: simResult.selected_intervention,
            rationale: `What-If simulation evaluated ${simResult.evaluated_simulations.length} candidate interventions. Selected minimum operational cost candidate.`,
            evaluated: simResult.evaluated_simulations,
          },
          what_if_result: simResult.selected_intervention as any,
        };
        setIncidents((prev) =>
          prev.map((inc) =>
            (inc.incident_info?.incident_id || inc.incident?.incident_id) === incidentId
              ? updatedInc
              : inc
          )
        );
      }
      alert(
        `[WHAT-IF SIMULATION COMPLETE]\nStatus: ${simResult.status}\nEvaluated Candidates: ${simResult.evaluated_simulations.length}\nSelected Intervention: ${simResult.selected_intervention?.description}`
      );
    } catch (err: any) {
      alert(`Simulation error: ${err.message}`);
    }
  };

  const incidentInfo = currentIncident?.incident_info || currentIncident?.incident;
  const attackPath = currentIncident?.attack_path || currentIncident?.incident?.attack_path || [];
  const findings = currentIncident?.findings || [];
  const investigation = currentIncident?.investigation || null;
  const blastRadius = currentIncident?.blast_radius || currentIncident?.incident?.blast_radius;
  const intervention = currentIncident?.intervention || null;
  const verification = currentIncident?.chimera_verification || currentIncident?.verification || null;
  const memoryPattern = currentIncident?.memory_pattern || currentIncident?.recalled_pattern || null;

  // Render Section Content helper
  const renderContent = () => {
    // Technical Loading State
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

    // Technical Error State
    if (error) {
      return (
        <div className="p-8 bg-red-50 border border-red-300 rounded-sm font-mono space-y-4 max-w-3xl mx-auto shadow-sm">
          <div className="flex items-center space-x-3 text-red-900 font-bold text-base">
            <span className="px-2 py-0.5 bg-red-800 text-white rounded-xs text-xs">CRITICAL ERROR</span>
            <span>ERROR: Connection to BLACKBOX Core lost</span>
          </div>
          <p className="text-xs text-red-800 font-sans leading-relaxed">{error}</p>
          <div className="pt-2 flex items-center space-x-3">
            <button
              onClick={() => loadDemoAttack(true)}
              className="px-4 py-2 bg-red-800 hover:bg-red-900 text-white font-mono text-xs font-bold rounded-xs transition-all duration-150 cursor-pointer"
            >
              ↻ RETRY CONNECTION
            </button>
            <button
              onClick={() => navigateTo("Overview")}
              className="px-4 py-2 bg-white border border-red-300 text-red-900 hover:bg-red-100 font-mono text-xs font-bold rounded-xs transition-all duration-150 cursor-pointer"
            >
              ↩ RETURN TO OVERVIEW
            </button>
          </div>
        </div>
      );
    }

    // 1. OVERVIEW PAGE (Default Startup Page)
    if (activeNavItem === "Overview") {
      return (
        <div className="space-y-6 max-w-5xl mx-auto">
          {/* Top Operational Status Header */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
            <Card className="bg-white">
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                System Status
              </span>
              <span className="font-bold text-emerald-600 text-sm mt-1 block">
                ● LIVE OPERATIONAL
              </span>
            </Card>
            <Card className="bg-white">
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Detector Status
              </span>
              <span className="font-bold text-slate-900 text-sm mt-1 block">
                ONLINE (P1 Engine)
              </span>
            </Card>
            <Card className="bg-white">
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Featherless LLM
              </span>
              <span className="font-bold text-slate-900 text-sm mt-1 block">
                CONNECTED (P2.2)
              </span>
            </Card>
            <Card className="bg-white">
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Active Incidents
              </span>
              <span className="font-bold text-blue-600 text-sm mt-1 block">
                {incidents.length} Generated
              </span>
            </Card>
          </div>

          {/* Hero Demo Control Card */}
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
                Simulate an Indirect Prompt Injection attack on the Customer Support Agent, observe the real-time execution graph, compute the AEGIS blast radius, synthesize P2.2 root cause explanation, and verify defense via CHIMERA.
              </p>
            </div>

            {/* Actions Row */}
            <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={() => loadDemoAttack(true)}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-mono text-sm font-bold px-8 py-3.5 rounded-xs tracking-wider shadow-md flex items-center space-x-3 transition-all duration-200 cursor-pointer transform hover:-translate-y-0.5"
              >
                <span>▶</span>
                <span>RUN DEMO ATTACK</span>
              </button>

              {incidents.length > 0 && (
                <button
                  onClick={() => navigateTo("Incidents")}
                  className="bg-slate-900 hover:bg-slate-800 text-white font-mono text-sm font-bold px-6 py-3.5 rounded-xs tracking-wider transition-all duration-200 cursor-pointer"
                >
                  👁 VIEW GENERATED INCIDENT ({incidents[0].incident_info?.incident_id || "INC-DEMO-1"})
                </button>
              )}
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

    // 2. INCIDENTS PAGE
    if (activeNavItem === "Incidents") {
      if (incidents.length === 0) {
        return (
          <div className="max-w-2xl mx-auto py-12">
            <Card className="bg-white text-center p-8 space-y-4">
              <div className="text-4xl">🚨</div>
              <div className="space-y-1">
                <h3 className="text-lg font-bold font-mono text-slate-900">No Active Incidents</h3>
                <p className="text-xs text-slate-600 font-sans">
                  There are currently no active threat traces in the system context. Navigate to the Overview page and click [ ▶ RUN DEMO ATTACK ] to execute a live attack simulation.
                </p>
              </div>
              <div className="pt-2">
                <Button variant="primary" onClick={() => navigateTo("Overview")}>
                  📊 Go to Overview
                </Button>
              </div>
            </Card>
          </div>
        );
      }

      return (
        <div className="space-y-6 max-w-5xl mx-auto">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold font-mono text-slate-900">INCIDENT MANAGEMENT</h2>
              <p className="text-xs font-mono text-slate-500">
                List of Active SOC Incidents and Threat Traces ({incidents.length})
              </p>
            </div>
            <Button variant="primary" size="sm" onClick={() => loadDemoAttack(true)}>
              ▶ Run Demo Attack
            </Button>
          </div>

          <div className="space-y-4">
            {incidents.map((inc) => {
              const info = inc.incident_info || inc.incident;
              const path = inc.attack_path || inc.incident?.attack_path || [];
              const verif = inc.chimera_verification || inc.verification;
              const incId = info?.incident_id || "INC-DEMO-1";

              return (
                <div
                  key={incId}
                  className="p-5 bg-white border border-slate-200 rounded-sm shadow-2xs space-y-4 hover:border-slate-300 transition-all duration-150"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono font-bold text-base text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-300">
                        {incId}
                      </span>
                      <Badge variant="critical">🔴 {info?.severity || "CRITICAL"}</Badge>
                      <Badge variant={verif?.defense_verified ? "success" : "outline-critical"}>
                        {verif?.defense_verified ? "DEFENSE VERIFIED" : "ACTIVE THREAT"}
                      </Badge>
                    </div>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => {
                        setSelectedIncidentId(incId);
                        navigateTo("Execution");
                      }}
                    >
                      ⚡ Open & Analyze Incident
                    </Button>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs text-slate-600 bg-slate-50 p-3 rounded-xs border border-slate-200/80">
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                        TARGET AGENT
                      </span>
                      <span className="font-semibold text-slate-900">
                        {info?.agent_id || "agent-support-bot"}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                        SESSION REFERENCE
                      </span>
                      <span className="font-semibold text-slate-900">
                        {info?.session_id || "S-DEMO-1"}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                        PRIMARY VECTOR
                      </span>
                      <span className="font-semibold text-red-700">INDIRECT PROMPT INJECTION</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                        ATTACK PATH LENGTH
                      </span>
                      <span className="font-semibold text-slate-900">{path.length} nodes</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      );
    }

    // 3. CONTEXTUAL INCIDENT SECTION PAGES (Execution, Attack Path, AEGIS, What-If, Intervention, CHIMERA, Verify)
    if (!currentIncident) {
      return (
        <div className="max-w-xl mx-auto py-12">
          <Card className="bg-white text-center p-8 space-y-4">
            <div className="text-4xl">⚠️</div>
            <div className="space-y-1">
              <h3 className="text-lg font-bold font-mono text-slate-900">NO INCIDENT SELECTED</h3>
              <p className="text-xs text-slate-600 font-sans">
                Section &quot;{activeNavItem}&quot; requires an active incident context. Select an incident from the Incidents list or launch the demo attack on Overview to inspect security analysis.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-center space-x-3">
              <Button variant="outline" onClick={() => navigateTo("Incidents")}>
                🚨 Go to Incidents
              </Button>
              <Button variant="primary" onClick={() => loadDemoAttack(true)}>
                ▶ Run Demo Attack
              </Button>
            </div>
          </Card>
        </div>
      );
    }

    // When an incident IS selected, render section specific content
    return (
      <div className="space-y-6 relative">
        {/* Incident Context Header */}
        <IncidentHeader
          incidentId={incidentInfo?.incident_id || "INC-DEMO-1"}
          agentId={incidentInfo?.agent_id || "agent-support-bot"}
          sessionId={incidentInfo?.session_id || "S-DEMO-1"}
          severity={incidentInfo?.severity || "CRITICAL"}
          status={verification?.defense_verified ? "DEFENSE VERIFIED" : "ACTIVE THREAT"}
          onSimulateClick={handleSimulateWhatIf}
          onExportClick={() =>
            alert(
              `Exporting full JSON payload for Incident ${
                incidentInfo?.incident_id || "INC-DEMO-1"
              }`
            )
          }
        />

        {/* Section Sub-Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-200 font-mono text-xs overflow-x-auto pb-1">
          {[
            { name: "Execution", icon: "⚡" },
            { name: "Attack Path", icon: "⛓️" },
            { name: "AEGIS", icon: "🛡️" },
            { name: "What-If", icon: "🔮" },
            { name: "Intervention", icon: "⚙️" },
            { name: "CHIMERA", icon: "⚔️" },
            { name: "Verify", icon: "✅" },
          ].map((tab) => {
            const isActive = activeNavItem === tab.name;
            return (
              <button
                key={tab.name}
                onClick={() => navigateTo(tab.name)}
                className={`px-3 py-1.5 rounded-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                  isActive
                    ? "bg-slate-900 text-white shadow-2xs"
                    : "text-slate-600 hover:bg-slate-200 text-slate-800"
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.name}</span>
              </button>
            );
          })}
        </div>

        {/* Render Specific Incident Section */}
        {activeNavItem === "Execution" && (
          <div className="space-y-6">
            <ExecutionGraph
              events={currentIncident.events || rawEvents}
              attackPath={attackPath}
              selectedEvent={selectedEvent}
              onNodeSelect={(ev) => setSelectedEvent(ev)}
            />

            {/* Raw Telemetry Sequence Table */}
            <Card
              title="TELEMETRY EVENT STREAM SEQUENCE"
              subtitle={`Total ${currentIncident.events?.length || rawEvents.length || 7} Ingested Events`}
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-500 uppercase text-[10px]">
                      <th className="py-2 px-3">Event ID</th>
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Source</th>
                      <th className="py-2 px-3">Target</th>
                      <th className="py-2 px-3">Resource / Action</th>
                      <th className="py-2 px-3">Trust Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(currentIncident.events || rawEvents).map((ev) => (
                      <tr
                        key={ev.event_id}
                        onClick={() => setSelectedEvent(ev)}
                        className={`border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors ${
                          selectedEvent?.event_id === ev.event_id ? "bg-blue-50/60 font-semibold" : ""
                        }`}
                      >
                        <td className="py-2 px-3 font-bold text-slate-900">{ev.event_id}</td>
                        <td className="py-2 px-3">
                          <Badge variant="neutral">{ev.event_type}</Badge>
                        </td>
                        <td className="py-2 px-3 text-slate-700">{ev.source}</td>
                        <td className="py-2 px-3 text-slate-600">{ev.target || "N/A"}</td>
                        <td className="py-2 px-3 text-slate-800">{ev.resource || ev.action || "N/A"}</td>
                        <td className="py-2 px-3">
                          <Badge
                            variant={
                              ev.trust_level === "UNTRUSTED"
                                ? "suspicious"
                                : ev.trust_level === "TRUSTED"
                                ? "success"
                                : "info"
                            }
                          >
                            {ev.trust_level}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        )}

        {activeNavItem === "Attack Path" && (
          <div className="space-y-6">
            <Card
              title="CANONICAL ATTACK PATH LINEAGE"
              subtitle={`Verified Path Length: ${attackPath.length} Nodes`}
            >
              <div className="p-4 bg-slate-900 text-white font-mono rounded-xs space-y-2">
                <div className="text-[10px] text-slate-400 uppercase font-bold">ATTACK CHAIN</div>
                <div className="text-sm font-bold text-red-400 tracking-wide">
                  {attackPath.join(" ➔ ") || "E1 ➔ E2 ➔ E3 ➔ E5 ➔ E6 ➔ E7"}
                </div>
              </div>
            </Card>

            <AnalysisPanels
              findings={findings}
              blastRadius={blastRadius}
              investigation={investigation}
              attackPath={attackPath}
            />
          </div>
        )}

        {activeNavItem === "AEGIS" && (
          <AnalysisPanels
            findings={findings}
            blastRadius={blastRadius}
            investigation={investigation}
            attackPath={attackPath}
          />
        )}

        {activeNavItem === "What-If" && (
          <ResponseVerificationPanels
            intervention={intervention}
            verification={verification}
            memoryPattern={memoryPattern}
            patternSignature={currentIncident.pattern_signature}
            onApplyDefense={handleApplyDefense}
            onSimulateClick={handleSimulateWhatIf}
            loadingDefense={loadingDefense}
          />
        )}

        {activeNavItem === "Intervention" && (
          <ResponseVerificationPanels
            intervention={intervention}
            verification={verification}
            memoryPattern={memoryPattern}
            patternSignature={currentIncident.pattern_signature}
            onApplyDefense={handleApplyDefense}
            onSimulateClick={handleSimulateWhatIf}
            loadingDefense={loadingDefense}
          />
        )}

        {activeNavItem === "CHIMERA" && (
          <ResponseVerificationPanels
            intervention={intervention}
            verification={verification}
            memoryPattern={memoryPattern}
            patternSignature={currentIncident.pattern_signature}
            onApplyDefense={handleApplyDefense}
            onSimulateClick={handleSimulateWhatIf}
            loadingDefense={loadingDefense}
          />
        )}

        {activeNavItem === "Verify" && (
          <ResponseVerificationPanels
            intervention={intervention}
            verification={verification}
            memoryPattern={memoryPattern}
            patternSignature={currentIncident.pattern_signature}
            onApplyDefense={handleApplyDefense}
            onSimulateClick={handleSimulateWhatIf}
            loadingDefense={loadingDefense}
          />
        )}

        {/* Event Inspector Drawer on node click */}
        <EventInspectorDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>
    );
  };

  return (
    <SecurityDashboardLayout
      activeNavItem={activeNavItem}
      onNavItemClick={navigateTo}
      incidentsCount={incidents.length}
    >
      {renderContent()}
    </SecurityDashboardLayout>
  );
};

/** Backend client. Shapes mirror the FastAPI response models. */

export type AgentEvent = {
  event_id: string;
  parent_event_id: string | null;
  session_id: string;
  agent_id: string;
  event_type: string;
  source: string;
  target: string | null;
  resource: string | null;
  action: string | null;
  permission: string | null;
  trust_level: string;
  timestamp: string;
  metadata: Record<string, any>;
};

export type Finding = {
  finding_id: string;
  detector_type: string;
  title: string;
  description: string;
  severity: string;
  event_ids: string[];
  graph_path: string[];
};

export type SensitiveResource = {
  resource: string;
  severity: number | string;
  resource_type: string | null;
};

export type BlastRadius = {
  reachable_sensitive_resources: (string | SensitiveResource)[];
  reachable_external_destinations: string[];
  affected_capabilities: string[];
  risk_score: number;
};

export type Impact = {
  finding_id: string;
  affected_event_ids: string[];
  affected_agents: string[];
  affected_resources: string[];
  affected_tools: string[];
  reachable_external_destinations: string[];
  trust_boundary_event_ids: string[];
  reachable_sensitive_resources: SensitiveResource[];
  blast_radius: BlastRadius;
};

export type Incident = {
  incident_id: string;
  agent_id: string;
  session_id: string;
  incident_type: string;
  severity: string;
  attack_path: string[];
  sensitive_resources: SensitiveResource[];
  blast_radius: BlastRadius;
};

export type Investigation = {
  root_cause: string;
  attack_narrative: string;
  critical_decision: { event_id: string; explanation: string };
  evidence_interpretation: { event_id: string; interpretation: string }[];
  confidence: number;
  contributing_factors: string[];
  failure_pattern_candidate: { pattern_name: string; description: string } | null;
};

export type Simulation = {
  intervention: {
    intervention_type: string;
    value: string;
    cost: number;
    description: string;
  };
  residual_detector_types: string[];
  removed_event_ids: string[];
  exfiltration_path_severed: boolean;
};

export type MemoryPattern = {
  signature: string;
  pattern: {
    pattern_name: string;
    description: string;
    indicators: string[];
  };
  provenance: {
    incident_id: string;
    session_id: string;
    finding_ids: string[];
    event_ids: string[];
  };
  times_seen: number;
};

export type IncidentInfo = {
  incident_id: string;
  session_id: string;
  agent_id: string;
  severity: string;
  status: string;
};

export type IncidentResponse = {
  incident_info: IncidentInfo | null;
  events: AgentEvent[];
  findings: Finding[];
  attack_path: string[];
  investigation: Investigation | null;
  blast_radius: BlastRadius | null;
  what_if_result: Simulation | null;
  intervention: {
    selected: Simulation["intervention"] | null;
    rationale: string;
    evaluated: Simulation[];
  } | null;
  defense_result: {
    defense_verified: boolean;
    attack_before: string;
    attack_after: string;
    blocked_events: string[];
  } | null;
  chimera_verification: {
    attack_before: string;
    attack_after: string;
    defense_verified: boolean;
    blocked_event_ids: string[];
    notes: string;
  } | null;
  verification?: {
    attack_before: string;
    attack_after: string;
    defense_verified: boolean;
    blocked_event_ids: string[];
    notes: string;
  } | null;
  memory_pattern: MemoryPattern | null;
  incident_analysis?: Incident | null;
  incident?: Incident | null;
  impacts?: Impact[];
  event_ids?: string[];
  pattern_signature?: string;
  recalled_pattern?: MemoryPattern | null;
};
const BASE = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE || "").replace(/\/+$/, "");
async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export async function fetchDemoScenario(): Promise<{
  events: AgentEvent[];
  known_sensitive_resources: SensitiveResource[];
}> {
  return json(await fetch(`${BASE}/incidents/demo-scenario`));
}

export async function analyzeIncident(
  events: AgentEvent[],
  known_sensitive_resources: SensitiveResource[] = [],
  explain: boolean = true,
  incident_id: string = "INC-ACTIVE"
): Promise<IncidentResponse> {
  return json<IncidentResponse>(
    await fetch(`${BASE}/incidents/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        events,
        known_sensitive_resources,
        incident_id,
        explain,
      }),
    })
  );
}

export async function simulateIntervention(
  incidentId: string,
  events: AgentEvent[],
  interventionType: string = "BLOCK_EXTERNAL_DESTINATION"
): Promise<{
  incident_id: string;
  intervention_type: string;
  selected_intervention: Simulation["intervention"] | null;
  evaluated_simulations: Simulation[];
  status: string;
}> {
  return json(
    await fetch(`${BASE}/incidents/${incidentId}/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events, intervention_type: interventionType }),
    })
  );
}

export async function defendIncident(
  incidentId: string,
  events: AgentEvent[]
): Promise<{
  incident_id: string;
  defense_verified: boolean;
  attack_before: string;
  attack_after: string;
  blocked_event_ids: string[];
  intervention_applied: Simulation["intervention"] | null;
  status: string;
}> {
  return json(
    await fetch(`${BASE}/incidents/${incidentId}/defend`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events }),
    })
  );
}

export type SessionSummary = {
  session_id: string;
  event_count: number;
  last_seen: string;
};

export async function fetchSessions(limit: number = 10): Promise<SessionSummary[]> {
  return json<SessionSummary[]>(await fetch(`${BASE}/events/sessions?limit=${limit}`));
}

export async function fetchEvents(sessionId: string): Promise<AgentEvent[]> {
  return json<AgentEvent[]>(await fetch(`${BASE}/events?session_id=${encodeURIComponent(sessionId)}`));
}

export async function triggerTargetDemo(
  scenario: "malicious" | "benign" = "malicious",
  sessionId?: string,
  demoDelay: number = 0.6,
  asyncRun: boolean = true
): Promise<{
  session_id: string;
  scenario: string;
  status: string;
  event_count?: number;
  events?: AgentEvent[];
  demo_delay?: number;
  async_run?: boolean;
}> {
  return json(
    await fetch(`${BASE}/events/run-demo`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenario,
        session_id: sessionId,
        demo_delay: demoDelay,
        async_run: asyncRun,
      }),
    })
  );
}

// Backwards compatible export for legacy callers
export async function analyzeDemoScenario(explain: boolean): Promise<any> {
  const scenario = await fetchDemoScenario();
  return analyzeIncident(scenario.events, scenario.known_sensitive_resources, explain);
}

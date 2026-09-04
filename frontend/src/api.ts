/** Backend client. Shapes mirror the FastAPI response models. */

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
  severity: number;
  resource_type: string | null;
};

export type BlastRadius = {
  reachable_sensitive_resources: string[];
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
  intervention: { intervention_type: string; value: string; cost: number; description: string };
  residual_detector_types: string[];
  removed_event_ids: string[];
  exfiltration_path_severed: boolean;
};

export type IncidentReport = {
  session_id: string;
  event_ids: string[];
  findings: Finding[];
  impacts: Impact[];
  incident: Incident | null;
  investigation: Investigation | null;
  intervention: {
    selected: Simulation["intervention"] | null;
    rationale: string;
    evaluated: Simulation[];
  };
  verification: {
    attack_before: string;
    attack_after: string;
    defense_verified: boolean;
    blocked_event_ids: string[];
    notes: string;
  };
};

const BASE = import.meta.env.VITE_API_BASE ?? "";

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export async function analyzeDemoScenario(explain: boolean): Promise<IncidentReport> {
  const scenario = await json<{ events: unknown[]; known_sensitive_resources: unknown[] }>(
    await fetch(`${BASE}/incidents/demo-scenario`),
  );

  return json<IncidentReport>(
    await fetch(`${BASE}/incidents/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...scenario, incident_id: "INC-DEMO", explain }),
    }),
  );
}

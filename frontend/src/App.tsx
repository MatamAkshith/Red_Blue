import { useEffect, useState } from "react";
import { analyzeDemoScenario, type IncidentReport } from "./api";

function Panel({
  title,
  children,
  span = false,
}: {
  title: string;
  children: React.ReactNode;
  span?: boolean;
}) {
  return (
    <section
      className={`rounded-lg border border-neutral-800 bg-neutral-900 p-4 ${
        span ? "sm:col-span-2 lg:col-span-3" : ""
      }`}
    >
      <h2 className="mb-2 text-sm font-medium text-neutral-200">{title}</h2>
      <div className="text-xs text-neutral-400">{children}</div>
    </section>
  );
}

function Chain({ ids }: { ids: string[] }) {
  if (!ids.length) return <span className="text-neutral-500">none</span>;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {ids.map((id, i) => (
        <span key={`${id}-${i}`} className="flex items-center gap-1">
          <code className="rounded bg-neutral-800 px-1.5 py-0.5 text-neutral-200">{id}</code>
          {i < ids.length - 1 && <span className="text-neutral-600">→</span>}
        </span>
      ))}
    </div>
  );
}

function App() {
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [explain, setExplain] = useState(false);

  const run = (withExplanation: boolean) => {
    setLoading(true);
    setError(null);
    analyzeDemoScenario(withExplanation)
      .then(setReport)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => run(false), []);

  const verified = report?.verification.defense_verified;
  const uniq = (xs: string[]) => [...new Set(xs)];
  // Aggregate across every impact: a single "widest" impact can miss facts
  // another finding established (e.g. the external destination).
  const allExternal = uniq(
    report?.impacts.flatMap((i) => i.reachable_external_destinations) ?? [],
  );
  const allTools = uniq(report?.impacts.flatMap((i) => i.affected_tools) ?? []);
  const allTrustBoundary = uniq(
    report?.impacts.flatMap((i) => i.trust_boundary_event_ids) ?? [],
  );
  const maxRisk = Math.max(0, ...(report?.impacts.map((i) => i.blast_radius.risk_score) ?? [0]));

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-800 px-6 py-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">BLACKBOX</h1>
          <p className="text-sm text-neutral-400">
            Adaptive Security &amp; Forensic Intelligence for AI Agents
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-neutral-400">
            <input
              type="checkbox"
              checked={explain}
              onChange={(e) => setExplain(e.target.checked)}
              className="accent-neutral-400"
            />
            Featherless explanation
          </label>
          <button
            type="button"
            onClick={() => run(explain)}
            disabled={loading}
            className="rounded border border-neutral-700 bg-neutral-800 px-3 py-1.5 text-xs font-medium text-neutral-100 hover:bg-neutral-700 disabled:opacity-50"
          >
            {loading ? "Analyzing…" : "Run demo attack"}
          </button>
        </div>
      </header>

      {error && (
        <div className="mx-6 mt-4 rounded border border-red-900 bg-red-950 px-4 py-3 text-sm text-red-200">
          Backend error: {error}
        </div>
      )}

      {loading && !report && (
        <p className="px-6 py-8 text-sm text-neutral-500">Running the pipeline…</p>
      )}

      {report && (
        <main className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2 lg:grid-cols-3">
          <Panel title="Security status">
            <p
              className={`text-base font-semibold ${
                verified ? "text-emerald-400" : "text-red-400"
              }`}
            >
              {verified ? "DEFENSE VERIFIED" : "EXPOSED"}
            </p>
            <p className="mt-1">
              {report.findings.length} finding(s) · severity{" "}
              {report.incident?.severity ?? "—"}
            </p>
          </Panel>

          <Panel title="Agents">
            <p>
              <code className="text-neutral-200">{report.incident?.agent_id}</code>
            </p>
            <p className="mt-1">session {report.session_id}</p>
          </Panel>

          <Panel title="Incident details">
            <p>{report.incident?.incident_id}</p>
            <p className="mt-1">{report.incident?.incident_type}</p>
            <p className="mt-1">{report.event_ids.length} events analyzed</p>
          </Panel>

          <Panel title="Detection findings" span>
            <ul className="space-y-1">
              {report.findings.map((f) => (
                <li key={f.finding_id} className="flex flex-wrap items-baseline gap-2">
                  <span className="rounded bg-neutral-800 px-1.5 py-0.5 text-[10px] uppercase text-neutral-300">
                    {f.severity}
                  </span>
                  <span className="text-neutral-200">{f.detector_type}</span>
                  <span className="text-neutral-500">{f.event_ids.join(", ")}</span>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title="Attack path" span>
            <Chain ids={report.incident?.attack_path ?? []} />
          </Panel>

          <Panel title="Blast radius">
            <p>risk score {maxRisk}</p>
            <p className="mt-1">
              sensitive:{" "}
              {report.incident?.sensitive_resources.map((r) => r.resource).join(", ") || "none"}
            </p>
            <p className="mt-1">
              external: {allExternal.join(", ") || "none"}
            </p>
          </Panel>

          <Panel title="AEGIS impact">
            <p>{report.impacts.length} impact result(s)</p>
            <p className="mt-1">
              tools: {allTools.join(", ") || "none"}
            </p>
            <p className="mt-1">
              trust boundary: {allTrustBoundary.join(", ") || "none"}
            </p>
          </Panel>

          <Panel title="Recommended intervention">
            {report.intervention.selected ? (
              <>
                <p className="text-neutral-200">
                  {report.intervention.selected.intervention_type}
                </p>
                <p className="mt-1 break-all">{report.intervention.selected.value}</p>
                <p className="mt-1">cost {report.intervention.selected.cost}</p>
              </>
            ) : (
              <p>{report.intervention.rationale || "none required"}</p>
            )}
          </Panel>

          <Panel title="What-if simulations" span>
            <ul className="space-y-1">
              {report.intervention.evaluated.map((s) => (
                <li key={`${s.intervention.intervention_type}-${s.intervention.value}`}>
                  <span className={s.exfiltration_path_severed ? "text-emerald-400" : "text-neutral-500"}>
                    {s.exfiltration_path_severed ? "severs" : "insufficient"}
                  </span>{" "}
                  <span className="text-neutral-300">{s.intervention.description}</span>{" "}
                  <span className="text-neutral-500">
                    (cost {s.intervention.cost}, removes {s.removed_event_ids.length})
                  </span>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title="CHIMERA re-attack">
            <p>before: {report.verification.attack_before}</p>
            <p className="mt-1">after: {report.verification.attack_after}</p>
            <p className="mt-1">blocked: {report.verification.blocked_event_ids.join(", ") || "none"}</p>
          </Panel>

          <Panel title="Verification">
            <p className={verified ? "text-emerald-400" : "text-red-400"}>
              {verified ? "defense verified" : "not verified"}
            </p>
            <p className="mt-1">{report.verification.notes}</p>
          </Panel>

          <Panel title="Root cause" span>
            {report.investigation ? (
              <p className="text-neutral-300">{report.investigation.root_cause}</p>
            ) : (
              <p>
                Deterministic analysis only. Enable “Featherless explanation” for a
                narrative.
              </p>
            )}
          </Panel>

          {report.investigation && (
            <>
              <Panel title="Attack narrative" span>
                <p className="text-neutral-300">{report.investigation.attack_narrative}</p>
              </Panel>
              <Panel title="Critical decision">
                <p>
                  <code className="text-neutral-200">
                    {report.investigation.critical_decision.event_id}
                  </code>
                </p>
                <p className="mt-1">{report.investigation.critical_decision.explanation}</p>
              </Panel>
              <Panel title="Failure pattern">
                {report.investigation.failure_pattern_candidate ? (
                  <>
                    <p className="text-neutral-200">
                      {report.investigation.failure_pattern_candidate.pattern_name}
                    </p>
                    <p className="mt-1">
                      {report.investigation.failure_pattern_candidate.description}
                    </p>
                  </>
                ) : (
                  <p>none proposed</p>
                )}
              </Panel>
            </>
          )}
        </main>
      )}
    </div>
  );
}

export default App;

/**
 * Placeholder investigation workspace shell — lists the panels the spec
 * calls for. No live data wiring yet; each panel gets real content once
 * its backend module (see repo root README) is implemented.
 */

const PANELS = [
  "Security status",
  "Agents",
  "Active incidents",
  "Execution graph",
  "Incident details",
  "Attack path",
  "Root cause",
  "Critical decision",
  "Blast radius",
  "What-if controls",
  "Recommended intervention",
  "Simulate",
  "Verify",
  "Failure pattern",
] as const;

function App() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      <header className="border-b border-neutral-800 px-6 py-4">
        <h1 className="text-xl font-semibold tracking-tight">BLACKBOX</h1>
        <p className="text-sm text-neutral-400">
          Adaptive Security & Forensic Intelligence for AI Agents
        </p>
      </header>

      <main className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2 lg:grid-cols-3">
        {PANELS.map((panel) => (
          <section
            key={panel}
            className="rounded-lg border border-neutral-800 bg-neutral-900 p-4"
          >
            <h2 className="text-sm font-medium text-neutral-200">{panel}</h2>
            <p className="mt-1 text-xs text-neutral-500">Not wired up yet</p>
          </section>
        ))}
      </main>
    </div>
  );
}

export default App;

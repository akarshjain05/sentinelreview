import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, ErrorState, LoadingState } from "../components/Layout";

const AGENT_LABEL: Record<string, string> = {
  triage: "Triage",
  static_analysis: "Static Analysis",
  retrieval: "Retrieval",
  classification: "Classification",
  fix_suggestion: "Fix Suggestion",
  verification: "Verification",
  reporting: "Reporting",
};

function formatMs(ms: number | null): string {
  if (ms === null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`;
}

export function ObservabilityPage() {
  const state = useApiFetch(() => api.getLatencyStats());

  if (state.status === "loading") return <LoadingState label="Loading observability data" />;
  if (state.status === "error") return <ErrorState message={state.error} />;

  const data = state.data;

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-display text-2xl font-semibold">Observability</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Real per-agent latency and success rate, computed from every pipeline run's AgentRun rows.
        </p>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <div className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">Total reviews</div>
          <div className="mt-1 font-mono-data text-2xl font-semibold">{data.total_reviews}</div>
        </div>
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <div className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">Avg review latency</div>
          <div className="mt-1 font-mono-data text-2xl font-semibold">{formatMs(data.avg_review_latency_ms)}</div>
        </div>
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <div className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">Total cost</div>
          <div className="mt-1 font-mono-data text-2xl font-semibold">${data.total_cost_usd.toFixed(2)}</div>
        </div>
      </div>

      <div className="mb-6 rounded border border-[var(--color-scan)]/30 bg-[var(--color-scan)]/5 px-4 py-3 text-xs text-[var(--color-text-muted)]">
        {data.cost_tracking_note}
      </div>

      {data.per_agent.length === 0 ? (
        <EmptyState
          title="No pipeline runs yet"
          hint="Latency data appears here once at least one review has actually run through the pipeline."
        />
      ) : (
        <div className="overflow-hidden rounded border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
                <th className="px-4 py-3 font-medium">Agent</th>
                <th className="px-4 py-3 font-medium">Runs</th>
                <th className="px-4 py-3 font-medium">Avg latency</th>
                <th className="px-4 py-3 font-medium">Min / Max</th>
                <th className="px-4 py-3 font-medium">Success rate</th>
              </tr>
            </thead>
            <tbody>
              {data.per_agent.map((agent) => (
                <tr key={agent.agent_name} className="border-b border-[var(--color-border)] last:border-0">
                  <td className="px-4 py-3 font-medium">{AGENT_LABEL[agent.agent_name] ?? agent.agent_name}</td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text-muted)]">
                    {agent.run_count}
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text)]">
                    {formatMs(agent.avg_latency_ms)}
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text-faint)]">
                    {formatMs(agent.min_latency_ms)} / {formatMs(agent.max_latency_ms)}
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs">
                    <span
                      style={{
                        color:
                          agent.success_rate !== null && agent.success_rate < 1
                            ? "var(--color-high)"
                            : "var(--color-low)",
                      }}
                    >
                      {agent.success_rate !== null ? `${(agent.success_rate * 100).toFixed(0)}%` : "—"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

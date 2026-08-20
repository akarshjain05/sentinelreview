import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, ErrorState, LoadingState } from "../components/Layout";
import { SEVERITY_COLOR } from "../components/severityConstants";

export function AnalyticsPage() {
  const state = useApiFetch(() => api.getDashboardStats());

  if (state.status === "loading") {
    return <LoadingState label="Loading dashboard stats" />;
  }

  if (state.status === "error") {
    return <ErrorState message="Failed to load dashboard statistics." />;
  }

  const stats = state.data;
  const { findings_by_severity, findings_over_time, reviews_over_time } = stats;

  if (findings_by_severity.length === 0 && reviews_over_time.length === 0) {
    return <EmptyState title="No Analytics Data" hint="Ensure you have completed reviews to view stats." />;
  }

  const totalFindings = findings_by_severity.reduce((sum, item) => sum + item.count, 0);
  const totalReviews = reviews_over_time.reduce((sum, item) => sum + item.review_count, 0);
  const totalCost = reviews_over_time.reduce((sum, item) => sum + item.total_cost_usd, 0);

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight">Analytics</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          High-level overview of security findings and review activity.
        </p>
      </div>

      {/* Top Stats Cards */}
      <div className="grid gap-6 sm:grid-cols-3">
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm">
          <div className="text-sm font-medium text-[var(--color-text-muted)]">Total Findings</div>
          <div className="mt-2 text-3xl font-bold text-[var(--color-text)]">{totalFindings}</div>
        </div>
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm">
          <div className="text-sm font-medium text-[var(--color-text-muted)]">Total Reviews</div>
          <div className="mt-2 text-3xl font-bold text-[var(--color-text)]">{totalReviews}</div>
        </div>
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm">
          <div className="text-sm font-medium text-[var(--color-text-muted)]">Total Cost (USD)</div>
          <div className="mt-2 text-3xl font-bold text-[var(--color-text)]">${totalCost.toFixed(4)}</div>
        </div>
      </div>

      <div className="grid gap-8 lg:grid-cols-2">
        {/* Findings by Severity (Pie Chart) */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm">
          <h3 className="mb-6 text-lg font-medium text-[var(--color-text)]">Findings by Severity</h3>
          {findings_by_severity.length > 0 ? (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={findings_by_severity}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="count"
                    nameKey="severity"
                    label={(props: any) => `${props.severity}: ${props.count}`}
                  >
                    {findings_by_severity.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={SEVERITY_COLOR[entry.severity as keyof typeof SEVERITY_COLOR] || SEVERITY_COLOR.info}
                        stroke="rgba(255,255,255,0.1)"
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "var(--color-surface)", borderColor: "var(--color-border)", color: "var(--color-text)" }}
                    itemStyle={{ color: "var(--color-text)" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-72 items-center justify-center text-sm text-[var(--color-text-faint)]">
              No findings recorded yet.
            </div>
          )}
        </div>

        {/* Findings Over Time (Area Chart) */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm">
          <h3 className="mb-6 text-lg font-medium text-[var(--color-text)]">Findings Over Time</h3>
          {findings_over_time.length > 0 ? (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={findings_over_time}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-critical)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="var(--color-critical)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--color-text-faint)" tick={{ fill: "var(--color-text-faint)" }} />
                  <YAxis stroke="var(--color-text-faint)" tick={{ fill: "var(--color-text-faint)" }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "var(--color-surface)", borderColor: "var(--color-border)", color: "var(--color-text)" }}
                    itemStyle={{ color: "var(--color-critical)" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    name="Findings"
                    stroke="var(--color-critical)"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorCount)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-72 items-center justify-center text-sm text-[var(--color-text-faint)]">
              No findings over time data.
            </div>
          )}
        </div>
        
        {/* Reviews Over Time (Area Chart) */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl backdrop-blur-sm lg:col-span-2">
          <h3 className="mb-6 text-lg font-medium text-[var(--color-text)]">Review Activity Over Time</h3>
          {reviews_over_time.length > 0 ? (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={reviews_over_time}>
                  <defs>
                    <linearGradient id="colorReviewCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-scan)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="var(--color-scan)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--color-text-faint)" tick={{ fill: "var(--color-text-faint)" }} />
                  <YAxis stroke="var(--color-text-faint)" tick={{ fill: "var(--color-text-faint)" }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "var(--color-surface)", borderColor: "var(--color-border)", color: "var(--color-text)" }}
                    itemStyle={{ color: "var(--color-scan)" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="review_count"
                    name="Reviews"
                    stroke="var(--color-scan)"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorReviewCount)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
             <div className="flex h-72 items-center justify-center text-sm text-[var(--color-text-faint)]">
              No review data.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

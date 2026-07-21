import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, ErrorState, LoadingState } from "../components/Layout";
import { SeverityGauge } from "../components/Severity";
import type { ReviewStatus } from "../types";

const STATUS_LABEL: Record<ReviewStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  skipped: "Skipped",
};

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}

export function ReviewsListPage() {
  const state = useApiFetch(() => api.listReviews());

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-display text-2xl font-semibold">Reviews</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Every pull request SentinelReview has scanned, newest first.
        </p>
      </div>

      {state.status === "loading" && <LoadingState label="Loading reviews" />}
      {state.status === "error" && <ErrorState message={state.error} />}
      {state.status === "success" && state.data.length === 0 && (
        <EmptyState
          title="No reviews yet"
          hint="Reviews will appear here once a PR triggers a scan, or run the seed script for sample data."
        />
      )}

      {state.status === "success" && state.data.length > 0 && (
        <div className="overflow-hidden rounded border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
                <th className="px-4 py-3 font-medium">Pull request</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Findings</th>
                <th className="px-4 py-3 font-medium">Latency</th>
                <th className="px-4 py-3 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {state.data.map((review) => (
                <tr
                  key={review.id}
                  className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface)]"
                >
                  <td className="px-4 py-3">
                    <Link to={`/reviews/${review.id}`} className="group block">
                      <div className="font-medium text-[var(--color-text)] group-hover:text-[var(--color-scan)]">
                        {review.repo_full_name ?? "unknown repo"}
                        {review.pr_number != null && (
                          <span className="text-[var(--color-text-faint)]"> #{review.pr_number}</span>
                        )}
                      </div>
                      {review.pr_title && (
                        <div className="text-xs text-[var(--color-text-muted)]">{review.pr_title}</div>
                      )}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-[var(--color-text-muted)]">{STATUS_LABEL[review.status]}</td>
                  <td className="px-4 py-3">
                    <div className="mb-1 font-mono-data text-xs text-[var(--color-text-muted)]">
                      {review.finding_count}
                    </div>
                    <SeverityGauge counts={review.severity_counts} className="max-w-[120px]" />
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text-muted)]">
                    {review.total_latency_ms > 0 ? `${(review.total_latency_ms / 1000).toFixed(1)}s` : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--color-text-faint)]">
                    {formatRelativeTime(review.completed_at ?? review.started_at)}
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

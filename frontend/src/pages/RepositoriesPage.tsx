import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, ErrorState, LoadingState } from "../components/Layout";

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

export function RepositoriesPage() {
  const state = useApiFetch(() => api.listRepositories());

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-display text-2xl font-semibold">Repositories</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          All repositories monitored by SentinelReview.
        </p>
      </div>

      {state.status === "loading" && <LoadingState label="Loading repositories" />}
      {state.status === "error" && <ErrorState message={state.error} />}
      {state.status === "success" && state.data.length === 0 && (
        <EmptyState
          title="No repositories"
          hint="Install the SentinelReview GitHub App on your repositories to see them here."
        />
      )}

      {state.status === "success" && state.data.length > 0 && (
        <div className="overflow-hidden rounded border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
                <th className="px-4 py-3 font-medium">Repository</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Default Branch</th>
                <th className="px-4 py-3 font-medium">Reviews</th>
                <th className="px-4 py-3 font-medium">Added</th>
              </tr>
            </thead>
            <tbody>
              {state.data.map((repo) => (
                <tr
                  key={repo.id}
                  className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface)]"
                >
                  <td className="px-4 py-3">
                    <Link to={`/?repo=${encodeURIComponent(repo.full_name)}`} className="group block">
                      <div className="font-medium text-[var(--color-text)] group-hover:text-[var(--color-scan)]">
                        {repo.full_name}
                      </div>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    {repo.is_active ? (
                      <span className="inline-flex items-center rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-500">
                        Active
                      </span>
                    ) : (
                      <span className="inline-flex items-center rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-500">
                        Inactive
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text-muted)]">
                    {repo.default_branch}
                  </td>
                  <td className="px-4 py-3 font-mono-data text-xs text-[var(--color-text-muted)]">
                    {repo.review_count}
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--color-text-faint)]">
                    {formatRelativeTime(repo.created_at)}
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

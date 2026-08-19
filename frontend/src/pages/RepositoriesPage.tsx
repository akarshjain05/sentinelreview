import { useState } from "react";
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

function RepoToggle({ repo }: { repo: import("../types").RepositorySummary }) {
  const [isActive, setIsActive] = useState(repo.is_active);
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    setLoading(true);
    const prev = isActive;
    setIsActive(!prev); // Optimistic update
    try {
      await api.updateRepository(repo.id, { is_active: !prev });
    } catch (err) {
      console.error("Failed to toggle repo:", err);
      setIsActive(prev); // Revert on failure
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out outline-none focus:outline-none [-webkit-tap-highlight-color:transparent] ${
        isActive ? "bg-[var(--color-scan)]" : "bg-[var(--color-border)] hover:bg-gray-700"
      } ${loading ? "opacity-50 cursor-wait" : ""}`}
      role="switch"
      aria-checked={isActive}
    >
      <span className="sr-only">Toggle repository</span>
      <span
        aria-hidden="true"
        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full shadow ring-0 transition duration-200 ease-in-out ${
          isActive ? "translate-x-5 bg-[#0a0a0a]" : "translate-x-0 bg-gray-400"
        }`}
      />
    </button>
  );
}

export function RepositoriesPage() {
  const state = useApiFetch(() => api.listRepositories());

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-semibold">Repositories</h1>
          <p className="mt-1 text-sm text-[var(--color-text-muted)]">
            All repositories monitored by SentinelReview.
          </p>
        </div>
        <a 
          href="https://github.com/apps/sentinelreview-akarsh/installations/new" 
          target="_blank" 
          rel="noopener noreferrer"
          className="inline-flex items-center justify-center rounded bg-[var(--color-scan)] px-4 py-2 text-sm font-medium text-black hover:bg-[#2DD4BF] focus:outline-none focus:ring-2 focus:ring-[var(--color-scan)] focus:ring-offset-2 focus:ring-offset-[var(--color-bg)] transition-colors"
        >
          Add Repository
        </a>
      </div>

      {state.status === "loading" && <LoadingState label="Loading repositories" />}
      {state.status === "error" && <ErrorState message={state.error} />}
      {state.status === "success" && state.data.length === 0 && (
        <EmptyState
          title="No repositories"
          hint={
            <>
              Install the SentinelReview GitHub App on your repositories to see them here.{" "}
              <a 
                href="https://github.com/apps/sentinelreview-akarsh/installations/new" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-[var(--color-scan)] hover:underline font-medium"
              >
                Install App &rarr;
              </a>
            </>
          }
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
                    <Link to={`/reviews?repo=${encodeURIComponent(repo.full_name)}`} className="group block">
                      <div className="font-medium text-[var(--color-text)] group-hover:text-[var(--color-scan)]">
                        {repo.full_name}
                      </div>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <RepoToggle repo={repo} />
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

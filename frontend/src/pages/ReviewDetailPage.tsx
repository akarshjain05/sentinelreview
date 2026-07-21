import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, ErrorState, LoadingState } from "../components/Layout";
import { SeverityBadge, SeverityGauge } from "../components/Severity";
import type { Finding } from "../types";

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          {finding.cwe_id && (
            <span className="font-mono-data text-xs text-[var(--color-text-faint)]">{finding.cwe_id}</span>
          )}
        </div>
        <span className="font-mono-data text-xs text-[var(--color-text-faint)]" title="Which analyzer(s) found this">
          {finding.source}
        </span>
      </div>

      <div className="mb-2 font-mono-data text-sm text-[var(--color-text)]">
        {finding.file_path}
        <span className="text-[var(--color-text-faint)]">
          :{finding.start_line}
          {finding.end_line !== finding.start_line ? `-${finding.end_line}` : ""}
        </span>
      </div>

      <p className="mb-3 text-sm text-[var(--color-text-muted)]">{finding.explanation}</p>

      {finding.code_snippet && (
        <pre className="overflow-x-auto rounded bg-[var(--color-bg)] p-3 font-mono-data text-xs text-[var(--color-text)]">
          {finding.code_snippet}
        </pre>
      )}

      {finding.citations.length > 0 && (
        <div className="mt-3 border-t border-[var(--color-border)] pt-3">
          <div className="mb-1.5 text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
            Grounded in
          </div>
          <ul className="space-y-1">
            {finding.citations.map((citation) => (
              <li key={citation.external_id} className="text-xs text-[var(--color-text-muted)]">
                {citation.url ? (
                  <a
                    href={citation.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[var(--color-scan)] hover:underline"
                  >
                    {citation.title}
                  </a>
                ) : (
                  <span className="text-[var(--color-text)]">{citation.title}</span>
                )}
                <span className="text-[var(--color-text-faint)]"> · {citation.source}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {finding.patch_suggestions && finding.patch_suggestions.length > 0 && (
        <div className="mt-4 border-t border-[var(--color-border)] pt-3">
          <div className="mb-2 text-xs uppercase tracking-wide text-[var(--color-scan)]">
            Suggested Patches
          </div>
          <div className="space-y-4">
            {finding.patch_suggestions.map((patch) => (
              <div key={patch.id} className="rounded border border-[var(--color-border)] bg-[var(--color-bg)] p-3">
                <p className="mb-2 text-sm text-[var(--color-text-muted)]">{patch.reasoning}</p>
                <pre className="overflow-x-auto rounded bg-black p-3 font-mono-data text-xs text-white">
                  {patch.diff}
                </pre>
                
                {patch.verification_runs && patch.verification_runs.length > 0 && (
                  <div className="mt-3 space-y-2 border-t border-[var(--color-border)] pt-2">
                    <div className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">Verification Results</div>
                    {patch.verification_runs.map((vr) => (
                      <div key={vr.id} className="text-xs text-[var(--color-text-muted)]">
                        <div className="flex gap-4">
                          <span className={vr.issue_resolved ? "text-green-500" : "text-red-500"}>
                            {vr.issue_resolved ? "✓ Issue Resolved" : "✗ Issue Not Resolved"}
                          </span>
                          <span className={vr.tests_passed ? "text-green-500" : "text-red-500"}>
                            {vr.tests_passed ? "✓ Tests Passed" : "✗ Tests Failed"}
                          </span>
                          <span className={vr.build_succeeded ? "text-green-500" : "text-red-500"}>
                            {vr.build_succeeded ? "✓ Build Succeeded" : "✗ Build Failed"}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function ReviewDetailPage() {
  const { reviewId } = useParams<{ reviewId: string }>();
  const state = useApiFetch(() => api.getReview(reviewId!), [reviewId]);

  if (state.status === "loading") return <LoadingState label="Loading review" />;
  if (state.status === "error") return <ErrorState message={state.error} />;

  const review = state.data;

  return (
    <div>
      <div className="mb-6">
        <p className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
          {review.repo_full_name ?? "unknown repo"} {review.pr_number != null && `#${review.pr_number}`}
        </p>
        <h1 className="font-display text-2xl font-semibold">{review.pr_title ?? "Untitled PR"}</h1>

        <div className="mt-4 flex items-center gap-4">
          <SeverityGauge counts={review.severity_counts} className="max-w-xs" />
          <span className="whitespace-nowrap font-mono-data text-xs text-[var(--color-text-muted)]">
            {review.finding_count} finding{review.finding_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      {review.findings.length === 0 ? (
        <EmptyState title="No findings" hint="SentinelReview didn't flag anything in this PR." />
      ) : (
        <div className="space-y-3">
          {review.findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}

import type { Severity, SeverityCounts } from "../types";
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from "./severityConstants";

/** A small pill showing one severity level -- used inline next to a finding. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium font-mono-data uppercase tracking-wide"
      style={{
        color: SEVERITY_COLOR[severity],
        backgroundColor: `color-mix(in srgb, ${SEVERITY_COLOR[severity]} 15%, transparent)`,
        border: `1px solid color-mix(in srgb, ${SEVERITY_COLOR[severity]} 40%, transparent)`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[severity] }} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

/**
 * The signature element: severity isn't a decorative badge system bolted
 * onto a neutral palette -- it's rendered here as a literal horizontal
 * threat-level gauge, proportioned by how many findings of each severity
 * actually exist. This is the one place the color system and the real
 * data are the same visual object, reused across the review list and
 * review detail pages as the thing this tool is actually for: showing
 * you, at a glance, how bad a PR's findings are.
 */
export function SeverityGauge({ counts, className = "" }: { counts: SeverityCounts; className?: string }) {
  const total = SEVERITY_ORDER.reduce((sum, sev) => sum + counts[sev], 0);

  if (total === 0) {
    return (
      <div className={`h-1.5 w-full rounded-full bg-[var(--color-border)] ${className}`} aria-label="No findings" />
    );
  }

  return (
    <div
      className={`flex h-1.5 w-full overflow-hidden rounded-full ${className}`}
      role="img"
      aria-label={SEVERITY_ORDER.map((sev) => `${counts[sev]} ${sev}`).join(", ")}
    >
      {SEVERITY_ORDER.filter((sev) => counts[sev] > 0).map((sev) => (
        <div
          key={sev}
          style={{
            width: `${(counts[sev] / total) * 100}%`,
            backgroundColor: SEVERITY_COLOR[sev],
          }}
          title={`${counts[sev]} ${SEVERITY_LABEL[sev]}`}
        />
      ))}
    </div>
  );
}

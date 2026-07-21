import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/", label: "Reviews", end: true },
  { to: "/evaluation", label: "Evaluation" },
  { to: "/observability", label: "Observability" },
];

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="relative overflow-hidden border-b border-[var(--color-border)] bg-[var(--color-surface)]">
        <div
          className="scan-sweep pointer-events-none absolute inset-y-0 left-0 w-1/3 bg-gradient-to-r from-transparent via-[var(--color-scan)]/10 to-transparent"
          aria-hidden="true"
        />
        <div className="relative mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div
              className="flex h-8 w-8 items-center justify-center rounded border border-[var(--color-scan)]/40 text-[var(--color-scan)]"
              aria-hidden="true"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path
                  d="M8 1l6 2.5v4c0 4-2.5 6.5-6 7.5-3.5-1-6-3.5-6-7.5v-4L8 1z"
                  stroke="currentColor"
                  strokeWidth="1.3"
                />
              </svg>
            </div>
            <span className="font-display text-lg font-semibold tracking-tight">SentinelReview</span>
          </div>
          <nav className="flex gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-[var(--color-surface-raised)] text-[var(--color-text)]"
                      : "text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-12 text-sm text-[var(--color-text-muted)]" role="status">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--color-scan)]" />
      {label}…
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded border border-[var(--color-critical)]/30 bg-[var(--color-critical)]/5 px-4 py-3 text-sm text-[var(--color-critical)]">
      <span className="font-medium">Couldn't load this.</span> {message}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="rounded border border-dashed border-[var(--color-border-strong)] px-6 py-12 text-center">
      <p className="font-display text-base font-medium text-[var(--color-text)]">{title}</p>
      <p className="mt-1 text-sm text-[var(--color-text-muted)]">{hint}</p>
    </div>
  );
}

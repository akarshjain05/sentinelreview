import { ShieldCheck, Activity, Search, History } from "lucide-react";
import { Link } from "react-router-dom";
import { useAuth } from "../components/AuthProvider";

export function DashboardPage() {
  const { user } = useAuth();
  
  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 max-w-5xl mx-auto">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-tight">Welcome, {user?.login || "Sentinel"}!</h1>
        <p className="mt-2 text-base text-[var(--color-text-muted)]">
          Your codebase security at a glance.
        </p>
      </div>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        <Link to="/observability" className="group rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-md transition-all hover:border-[var(--color-scan)] hover:shadow-[var(--color-scan)]/10 hover:shadow-xl">
          <div className="flex items-center space-x-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-[var(--color-scan)]/10">
              <History className="h-6 w-6 text-[var(--color-scan)]" />
            </div>
            <div>
              <h3 className="font-semibold text-[var(--color-text)] group-hover:text-[var(--color-scan)] transition-colors">System Health</h3>
              <p className="text-sm text-[var(--color-text-muted)]">View agent latency & metrics</p>
            </div>
          </div>
        </Link>
        
        <Link to="/repositories" className="group rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-md transition-all hover:border-[var(--color-info)] hover:shadow-[var(--color-info)]/10 hover:shadow-xl">
          <div className="flex items-center space-x-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-[var(--color-info)]/10">
              <Search className="h-6 w-6 text-[var(--color-info)]" />
            </div>
            <div>
              <h3 className="font-semibold text-[var(--color-text)] group-hover:text-[var(--color-info)] transition-colors">Repositories</h3>
              <p className="text-sm text-[var(--color-text-muted)]">Manage scanned repos</p>
            </div>
          </div>
        </Link>
        
        <Link to="/analytics" className="group rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-md transition-all hover:border-[var(--color-warning)] hover:shadow-[var(--color-warning)]/10 hover:shadow-xl">
          <div className="flex items-center space-x-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-[var(--color-warning)]/10">
              <Activity className="h-6 w-6 text-[var(--color-warning)]" />
            </div>
            <div>
              <h3 className="font-semibold text-[var(--color-text)] group-hover:text-[var(--color-warning)] transition-colors">Analytics</h3>
              <p className="text-sm text-[var(--color-text-muted)]">Security trends</p>
            </div>
          </div>
        </Link>
      </div>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8 shadow-xl backdrop-blur-sm text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[var(--color-success)]/10 mb-4">
            <ShieldCheck className="h-8 w-8 text-[var(--color-success)]" />
          </div>
          <h2 className="text-xl font-semibold mb-2">SentinelReview is Active</h2>
          <p className="text-[var(--color-text-muted)] max-w-md mx-auto">
            SentinelReview is actively monitoring your repositories for security vulnerabilities. When a new Pull Request is opened, it will automatically be scanned.
          </p>
      </div>
    </div>
  );
}

import { api } from "../api/client";
import { ShieldAlert, CheckCircle2, Zap, GitPullRequest } from "lucide-react";

export function LandingPage() {
  const handleLogin = () => {
    window.location.href = `${api.baseUrl}/auth/login/github`;
  };

  return (
    <div className="flex min-h-[85vh] flex-col items-center pt-20">
      <div className="w-full max-w-4xl px-4 text-center">
        <div className="mb-6 flex justify-center">
          <ShieldAlert className="h-20 w-20 text-[var(--color-scan)]" />
        </div>
        
        <h1 className="mb-6 font-display text-5xl font-bold tracking-tight md:text-6xl">
          Automated security reviews <br className="hidden md:block" />
          for your pull requests
        </h1>
        
        <p className="mx-auto mb-10 max-w-2xl text-lg text-[var(--color-text-muted)]">
          SentinelReview acts as an agentic security engineer, catching critical vulnerabilities 
          in your PRs before they hit production, complete with automated patching and verification.
        </p>

        <button
          onClick={handleLogin}
          className="inline-flex items-center gap-3 rounded-full bg-[var(--color-text)] px-8 py-4 font-semibold text-[var(--color-bg)] transition-transform hover:scale-105 active:scale-95"
        >
          <svg viewBox="0 0 24 24" className="h-5 w-5 fill-current" aria-hidden="true">
            <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
          </svg>
          Log in with GitHub
        </button>

        <div className="mt-24 grid grid-cols-1 gap-8 border-t border-[var(--color-border)] pt-16 md:grid-cols-3">
          <div className="text-left">
            <div className="mb-4 inline-flex rounded-lg bg-blue-500/10 p-3 text-blue-500">
              <Zap className="h-6 w-6" />
            </div>
            <h3 className="mb-2 text-xl font-semibold">Agentic Analysis</h3>
            <p className="text-[var(--color-text-muted)]">
              Combines fast static analysis with deep LLM reasoning to filter out false positives and catch complex logical flaws.
            </p>
          </div>
          
          <div className="text-left">
            <div className="mb-4 inline-flex rounded-lg bg-[var(--color-scan)]/10 p-3 text-[var(--color-scan)]">
              <GitPullRequest className="h-6 w-6" />
            </div>
            <h3 className="mb-2 text-xl font-semibold">Native GitHub Integration</h3>
            <p className="text-[var(--color-text-muted)]">
              Runs automatically on every new PR. Security findings are posted directly as review comments where developers work.
            </p>
          </div>
          
          <div className="text-left">
            <div className="mb-4 inline-flex rounded-lg bg-green-500/10 p-3 text-green-500">
              <CheckCircle2 className="h-6 w-6" />
            </div>
            <h3 className="mb-2 text-xl font-semibold">Verified Patches</h3>
            <p className="text-[var(--color-text-muted)]">
              Suggests fixes and verifies them in an isolated sandbox to ensure tests still pass and the issue is actually resolved.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

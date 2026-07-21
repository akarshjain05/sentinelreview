import { Navigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../components/AuthProvider";
import { ShieldAlert } from "lucide-react";

export function LoginPage() {
  const { user } = useAuth();

  // If already logged in, redirect to home
  if (user) {
    return <Navigate to="/" replace />;
  }

  const handleLogin = () => {
    // Redirect to backend's GitHub auth route
    window.location.href = `${api.baseUrl}/auth/login/github`;
  };

  return (
    <div className="flex min-h-[80vh] flex-col items-center justify-center text-center">
      <ShieldAlert className="mb-6 h-16 w-16 text-[var(--color-scan)]" />
      <h1 className="mb-2 font-display text-3xl font-semibold">Welcome to SentinelReview</h1>
      <p className="mb-8 max-w-sm text-[var(--color-text-muted)]">
        Automated security reviews for your GitHub pull requests. Please log in to view your reviews.
      </p>
      <button
        onClick={handleLogin}
        className="flex items-center gap-2 rounded bg-[var(--color-text)] px-6 py-3 font-semibold text-[var(--color-bg)] transition hover:opacity-90"
      >
        <svg viewBox="0 0 24 24" className="h-5 w-5 fill-current">
          <path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.379.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.161 22 16.416 22 12c0-5.523-4.477-10-10-10z" />
        </svg>
        Log in with GitHub
      </button>
    </div>
  );
}

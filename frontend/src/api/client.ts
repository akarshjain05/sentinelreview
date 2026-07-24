import type { EvalLatestResponse, LatencyStatsResponse, ReviewDetail, ReviewSummary } from "../types";

// Configurable via Vite env var so a production build can point at a real
// deployed API instead of localhost -- not hardcoded, since this dashboard
// is meant to be deployed against whatever backend URL the user actually runs.
const rawApiBase = import.meta.env.VITE_API_BASE_URL;
if (!rawApiBase) {
  throw new Error("VITE_API_BASE_URL environment variable is not defined");
}
const API_BASE = rawApiBase;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include", // Send session cookie
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? detail;
    } catch {
      // response body wasn't JSON -- fall back to statusText, already set above
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

export const api = {
  baseUrl: API_BASE,
  listRepositories: () => request<import("../types").RepositorySummary[]>("/repositories"),
  listReviews: (repo?: string) => request<ReviewSummary[]>(repo ? `/reviews?repo=${encodeURIComponent(repo)}` : "/reviews"),
  getReview: (id: string) => request<ReviewDetail>(`/reviews/${id}`),
  getLatestEvaluation: () => request<EvalLatestResponse>("/evaluation/latest"),
  getLatencyStats: () => request<LatencyStatsResponse>("/observability/latency"),
  getSettings: () => request<import("../types").Settings>("/settings"),
  updateInstallation: (id: string, data: Partial<import("../types").InstallationSettings>) => 
    request<{status: string}>(`/settings/installations/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),
  updateRepository: (id: string, data: Partial<import("../types").RepositorySettings>) => 
    request<{status: string}>(`/settings/repositories/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }),
};

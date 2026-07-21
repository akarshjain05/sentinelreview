import type { EvalLatestResponse, LatencyStatsResponse, ReviewDetail, ReviewSummary } from "../types";

// Configurable via Vite env var so a production build can point at a real
// deployed API instead of localhost -- not hardcoded, since this dashboard
// is meant to be deployed against whatever backend URL the user actually runs.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

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
  listReviews: () => request<ReviewSummary[]>("/reviews"),
  getReview: (id: string) => request<ReviewDetail>(`/reviews/${id}`),
  getLatestEvaluation: () => request<EvalLatestResponse>("/evaluation/latest"),
  getLatencyStats: () => request<LatencyStatsResponse>("/observability/latency"),
};

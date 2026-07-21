import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ObservabilityPage } from "./ObservabilityPage";

// Shape matches exactly what backend/app/routers/observability.py's
// get_latency_stats() actually returns (verified by
// tests/test_observability_api.py on the Python side).
const SAMPLE_LATENCY_STATS = {
  per_agent: [
    { agent_name: "triage", run_count: 5, avg_latency_ms: 12.4, min_latency_ms: 8, max_latency_ms: 20, success_rate: 1.0 },
    { agent_name: "static_analysis", run_count: 5, avg_latency_ms: 2648.75, min_latency_ms: 200, max_latency_ms: 3200, success_rate: 0.8 },
  ],
  total_reviews: 5,
  avg_review_latency_ms: 2890.5,
  total_cost_usd: 0.0,
  cost_tracking_note: "cost_usd is not yet populated by any real LLM call in this pipeline.",
};

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("ObservabilityPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders real per-agent latency stats with human labels", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_LATENCY_STATS,
    });

    renderWithRouter(<ObservabilityPage />);

    await waitFor(() => {
      expect(screen.getByText("Triage")).toBeInTheDocument();
    });
    expect(screen.getByText("Static Analysis")).toBeInTheDocument();
    expect(screen.getByText("2.6s")).toBeInTheDocument(); // 2648.75ms formatted
    expect(screen.getByText("12ms")).toBeInTheDocument(); // 12.4ms formatted (sub-second)
  });

  it("formats success rate as a percentage and total review count correctly", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_LATENCY_STATS,
    });

    renderWithRouter(<ObservabilityPage />);

    await waitFor(() => {
      expect(screen.getByText("100%")).toBeInTheDocument();
    });
    expect(screen.getByText("80%")).toBeInTheDocument();
    const totalReviewsLabel = screen.getByText("Total reviews");
    expect(totalReviewsLabel.nextElementSibling).toHaveTextContent("5");
  });

  it("shows the honest cost tracking note, not a bare $0.00 with no explanation", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_LATENCY_STATS,
    });

    renderWithRouter(<ObservabilityPage />);

    await waitFor(() => {
      expect(screen.getByText(/not yet populated/i)).toBeInTheDocument();
    });
    expect(screen.getByText("$0.00")).toBeInTheDocument();
  });

  it("shows an empty state when no pipeline runs exist yet", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({
        per_agent: [], total_reviews: 0, avg_review_latency_ms: null,
        total_cost_usd: 0.0, cost_tracking_note: "n/a",
      }),
    });

    renderWithRouter(<ObservabilityPage />);

    await waitFor(() => {
      expect(screen.getByText(/no pipeline runs yet/i)).toBeInTheDocument();
    });
  });

  it("shows an error state when the request fails", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "Something broke" }),
    });

    renderWithRouter(<ObservabilityPage />);

    await waitFor(() => {
      expect(screen.getByText(/something broke/i)).toBeInTheDocument();
    });
  });
});

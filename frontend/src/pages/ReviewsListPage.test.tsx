import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewsListPage } from "./ReviewsListPage";

// Shape matches exactly what backend/app/routers/reviews.py's list_reviews()
// actually returns (verified by tests/test_dashboard_api.py on the Python
// side) -- not an invented mock shape that could silently drift from reality.
const SAMPLE_REVIEWS = [
  {
    id: "rev-1",
    status: "completed",
    repo_full_name: "akarsh/sentinelreview",
    pr_number: 42,
    pr_title: "Add search endpoint",
    started_at: "2026-07-10T10:00:00Z",
    completed_at: "2026-07-10T10:00:05Z",
    total_latency_ms: 2800,
    finding_count: 2,
    severity_counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
  },
];

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("ReviewsListPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows a loading state before data arrives", () => {
    (fetch as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {})); // never resolves
    renderWithRouter(<ReviewsListPage />);
    expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
  });

  it("renders review data once loaded", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_REVIEWS,
    });

    renderWithRouter(<ReviewsListPage />);

    await waitFor(() => {
      expect(screen.getByText(/akarsh\/sentinelreview/)).toBeInTheDocument();
    });
    expect(screen.getByText(/#42/)).toBeInTheDocument();
    expect(screen.getByText("Add search endpoint")).toBeInTheDocument();
  });

  it("shows an empty state when there are no reviews", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, json: async () => [] });

    renderWithRouter(<ReviewsListPage />);

    await waitFor(() => {
      expect(screen.getByText(/no reviews yet/i)).toBeInTheDocument();
    });
  });

  it("shows an error state when the API call fails", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "Database unavailable" }),
    });

    renderWithRouter(<ReviewsListPage />);

    await waitFor(() => {
      expect(screen.getByText(/database unavailable/i)).toBeInTheDocument();
    });
  });
});

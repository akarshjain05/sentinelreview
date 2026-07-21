import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewDetailPage } from "./ReviewDetailPage";

// Shape matches exactly what backend/app/routers/reviews.py's get_review()
// actually returns (verified by tests/test_dashboard_api.py on the Python
// side), including the citations resolution added alongside this page's
// citation-rendering UI.
const SAMPLE_REVIEW_DETAIL = {
  id: "rev-1",
  status: "completed",
  repo_full_name: "akarsh/sentinelreview",
  pr_number: 42,
  pr_title: "Add search endpoint",
  started_at: "2026-07-10T10:00:00Z",
  completed_at: "2026-07-10T10:00:05Z",
  total_cost_usd: 0,
  total_latency_ms: 2890,
  finding_count: 2,
  severity_counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
  findings: [
    {
      id: "finding-1",
      file_path: "app/search.py",
      start_line: 14,
      end_line: 14,
      cwe_id: "CWE-89",
      vulnerability_type: "sql_injection",
      severity: "high",
      confidence: 0.9,
      source: "bandit+semgrep+classifier",
      explanation: "Detected pattern consistent with CWE-89.",
      code_snippet: 'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
      citations: [
        { external_id: "CWE-89", title: "CWE-89: SQL Injection", source: "cwe", url: null },
      ],
    },
    {
      id: "finding-2",
      file_path: "app/config.py",
      start_line: 3,
      end_line: 3,
      cwe_id: "CWE-798",
      vulnerability_type: "hardcoded_secret",
      severity: "medium",
      confidence: 0.7,
      source: "semgrep+classifier",
      explanation: "Detected pattern consistent with CWE-798.",
      code_snippet: 'API_KEY = "sk_live_..."',
      citations: [],
    },
  ],
};

function renderAtReviewRoute() {
  return render(
    <MemoryRouter initialEntries={["/reviews/rev-1"]}>
      <Routes>
        <Route path="/reviews/:reviewId" element={<ReviewDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ReviewDetailPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders findings with severity, file location, and explanation", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_REVIEW_DETAIL,
    });

    renderAtReviewRoute();

    await waitFor(() => {
      expect(screen.getByText("Add search endpoint")).toBeInTheDocument();
    });
    expect(screen.getByText(/app\/search\.py/)).toBeInTheDocument();
    expect(screen.getByText("CWE-89")).toBeInTheDocument();
    expect(screen.getByText("CWE-798")).toBeInTheDocument();
  });

  it("renders a resolved citation with a link when a URL is present", async () => {
    const withUrl = {
      ...SAMPLE_REVIEW_DETAIL,
      findings: [
        {
          ...SAMPLE_REVIEW_DETAIL.findings[0],
          citations: [
            {
              external_id: "CWE-89",
              title: "CWE-89: SQL Injection",
              source: "cwe",
              url: "https://cwe.mitre.org/data/definitions/89.html",
            },
          ],
        },
        SAMPLE_REVIEW_DETAIL.findings[1],
      ],
    };

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, json: async () => withUrl });

    renderAtReviewRoute();

    await waitFor(() => {
      expect(screen.getByText("CWE-89: SQL Injection")).toBeInTheDocument();
    });
    const link = screen.getByRole("link", { name: "CWE-89: SQL Injection" });
    expect(link).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/89.html");
  });

  it("renders a citation as plain text (no link) when no URL is present", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_REVIEW_DETAIL, // finding-1's citation has url: null
    });

    renderAtReviewRoute();

    await waitFor(() => {
      expect(screen.getByText("CWE-89: SQL Injection")).toBeInTheDocument();
    });
    expect(screen.queryByRole("link", { name: "CWE-89: SQL Injection" })).not.toBeInTheDocument();
  });

  it("does not render a 'Grounded in' section for a finding with no citations", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => SAMPLE_REVIEW_DETAIL,
    });

    renderAtReviewRoute();

    await waitFor(() => {
      expect(screen.getByText("CWE-798")).toBeInTheDocument();
    });
    // Only one "Grounded in" label should appear (for finding-1), not two.
    expect(screen.getAllByText("Grounded in")).toHaveLength(1);
  });

  it("shows an error state for a review that doesn't exist", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Review not found" }),
    });

    renderAtReviewRoute();

    await waitFor(() => {
      expect(screen.getByText(/review not found/i)).toBeInTheDocument();
    });
  });
});

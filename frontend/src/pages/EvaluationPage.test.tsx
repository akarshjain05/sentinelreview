import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EvaluationPage } from "./EvaluationPage";

// These are the ACTUAL real numbers this project measured (see README.md
// "Semgrep" row and "HF classifier finding" section) -- not placeholder
// values, so this test doubles as a regression check that the page
// correctly renders the real shape evaluation/run_eval.py produces.
const REAL_EVAL_RESPONSE = {
  bandit_only: {
    results: [],
    metrics: {
      n_cases: 17,
      true_positives: 9,
      false_positives: 1,
      false_negatives: 1,
      true_negatives: 6,
      precision: 0.9,
      recall: 0.9,
      f1: 0.9,
      cwe_accuracy_when_detected: 1.0,
      total_batch_latency_ms: 164.0,
      avg_latency_per_file_in_batch_ms: 9.6,
    },
  },
  merged: {
    results: [],
    metrics: {
      n_cases: 17,
      true_positives: 10,
      false_positives: 1,
      false_negatives: 0,
      true_negatives: 6,
      precision: 0.909,
      recall: 1.0,
      f1: 0.952,
      cwe_accuracy_when_detected: 1.0,
      total_batch_latency_ms: 4123.0,
      avg_latency_per_file_in_batch_ms: 242.5,
    },
  },
};

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("EvaluationPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the real precision/recall/F1 numbers for both variants", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => REAL_EVAL_RESPONSE,
    });

    renderWithRouter(<EvaluationPage />);

    await waitFor(() => {
      expect(screen.getByText("Bandit only")).toBeInTheDocument();
    });
    expect(screen.getByText("Bandit + Semgrep")).toBeInTheDocument();

    // 0.900 appears for both precision and recall in the bandit-only variant.
    expect(screen.getAllByText("0.900").length).toBeGreaterThanOrEqual(2);
    // The merged variant's real, improved numbers. "1.000" is deliberately
    // NOT checked with a bare getByText here: in this real dataset both
    // "Recall" (1.0) and "CWE accuracy" (1.0) legitimately render as
    // "1.000" simultaneously, so a bare text query is ambiguous by design,
    // not by bug -- scope to the specific labeled stat card instead.
    expect(screen.getByText("0.909")).toBeInTheDocument();
    expect(screen.getByText("0.952")).toBeInTheDocument();
    const recallLabel = screen.getAllByText("Recall")[1]; // second "Recall" label = the merged variant's card
    expect(recallLabel.nextElementSibling).toHaveTextContent("1.000");
  });

  it("shows a helpful empty state with the exact command to run when no results exist", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "No eval results found on disk." }),
    });

    renderWithRouter(<EvaluationPage />);

    await waitFor(() => {
      expect(screen.getByText(/no eval results found/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/run_eval\.py/)).toBeInTheDocument();
  });
});

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import { useApiFetch } from "../api/useApiFetch";
import { EmptyState, LoadingState } from "../components/Layout";
import type { EvalMetrics, EvalVariant } from "../types";

const VARIANT_LABEL: Record<EvalVariant, string> = {
  bandit_only: "Bandit only",
  merged: "Bandit + Semgrep",
  merged_hf: "Bandit + Semgrep + HF diagnostics",
  bandit_only_hf: "Bandit only + HF diagnostics",
};

function MetricStat({ label, value, accent = false }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="text-xs uppercase tracking-wide text-[var(--color-text-faint)]">{label}</div>
      <div
        className={`mt-1 font-mono-data text-2xl font-semibold ${
          accent ? "text-[var(--color-scan)]" : "text-[var(--color-text)]"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function VariantMetrics({ variant, metrics }: { variant: EvalVariant; metrics: EvalMetrics }) {
  return (
    <div className="mb-8">
      <h2 className="mb-3 font-display text-lg font-medium">{VARIANT_LABEL[variant]}</h2>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <MetricStat label="Precision" value={metrics.precision.toFixed(3)} />
        <MetricStat label="Recall" value={metrics.recall.toFixed(3)} />
        <MetricStat label="F1" value={metrics.f1.toFixed(3)} accent />
        <MetricStat
          label="CWE accuracy"
          value={metrics.cwe_accuracy_when_detected != null ? metrics.cwe_accuracy_when_detected.toFixed(3) : "—"}
        />
      </div>
      <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <MetricStat label="True positives" value={String(metrics.true_positives)} />
        <MetricStat label="False positives" value={String(metrics.false_positives)} />
        <MetricStat label="False negatives" value={String(metrics.false_negatives)} />
        <MetricStat label="True negatives" value={String(metrics.true_negatives)} />
      </div>

      {metrics.classifier_diagnostics && (
        <div className="mt-3 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <div className="mb-2 text-xs uppercase tracking-wide text-[var(--color-text-faint)]">
            Classifier diagnostics (does not affect detection numbers above)
          </div>
          <p className="mb-3 text-xs text-[var(--color-text-muted)]">{metrics.classifier_diagnostics.note}</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <MetricStat
              label="Score on vulnerable"
              value={metrics.classifier_diagnostics.avg_target_label_score_when_vulnerable?.toFixed(3) ?? "—"}
            />
            <MetricStat
              label="Score on safe lookalikes"
              value={metrics.classifier_diagnostics.avg_target_label_score_when_safe_lookalike?.toFixed(3) ?? "—"}
            />
            <MetricStat
              label="Separation"
              value={metrics.classifier_diagnostics.separation?.toFixed(3) ?? "—"}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export function EvaluationPage() {
  const state = useApiFetch(() => api.getLatestEvaluation());

  if (state.status === "loading") return <LoadingState label="Loading evaluation results" />;
  if (state.status === "error") {
    return (
      <div>
        <h1 className="mb-4 font-display text-2xl font-semibold">Evaluation</h1>
        <EmptyState
          title="No eval results found"
          hint="Run `python3 evaluation/run_eval.py` (and optionally --bandit-only) from the project root, then reload this page."
        />
      </div>
    );
  }

  const variants = Object.entries(state.data) as [EvalVariant, { metrics: EvalMetrics }][];
  const chartData = ["precision", "recall", "f1"].map((metric) => {
    const row: Record<string, string | number> = { metric };
    for (const [variant, result] of variants) {
      row[VARIANT_LABEL[variant]] = result.metrics[metric as "precision" | "recall" | "f1"];
    }
    return row;
  });

  return (
    <div>
      <div className="mb-6">
        <h1 className="font-display text-2xl font-semibold">Evaluation</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Real results from the hand-labeled benchmark (evaluation/fixtures/python_vuln_benchmark.py), not simulated.
        </p>
      </div>

      {variants.length > 1 && (
        <div className="mb-8 h-64 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="metric" stroke="var(--color-text-muted)" fontSize={12} />
              <YAxis domain={[0, 1]} stroke="var(--color-text-muted)" fontSize={12} />
              <Tooltip
                contentStyle={{
                  background: "var(--color-surface-raised)",
                  border: "1px solid var(--color-border-strong)",
                  borderRadius: 4,
                  fontSize: 12,
                }}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {variants.map(([variant], i) => (
                <Bar
                  key={variant}
                  dataKey={VARIANT_LABEL[variant]}
                  fill={i === 0 ? "var(--color-info)" : "var(--color-scan)"}
                  radius={[2, 2, 0, 0]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {variants.map(([variant, result]) => (
        <VariantMetrics key={variant} variant={variant} metrics={result.metrics} />
      ))}
    </div>
  );
}

// Mirrors the actual FastAPI response shapes in
// backend/app/routers/reviews.py and evaluation.py -- kept as plain types
// (not code-generated) since the backend is small enough that manual sync
// is tractable; a larger project would generate these from the OpenAPI
// schema FastAPI already exposes at /openapi.json.

export type ReviewStatus = "queued" | "running" | "completed" | "failed" | "skipped";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RepositorySummary {
  id: string;
  full_name: string;
  default_branch: string;
  is_active: boolean;
  created_at: string;
  review_count: number;
}

export interface ReviewSummary {
  id: string;
  status: ReviewStatus;
  repo_full_name: string | null;
  pr_number: number | null;
  pr_title: string | null;
  started_at: string | null;
  completed_at: string | null;
  total_latency_ms: number;
  finding_count: number;
  severity_counts: SeverityCounts;
}

export interface Citation {
  external_id: string;
  title: string;
  source: string;
  url: string | null;
}

export interface VerificationRun {
  id: string;
  issue_resolved: boolean;
  tests_passed: boolean;
  build_succeeded: boolean;
  introduced_new_findings: boolean;
  sandbox_log: string | null;
  created_at: string;
}

export interface PatchSuggestion {
  id: string;
  diff: string;
  reasoning: string;
  citations: Citation[];
  verification_runs: VerificationRun[];
}

export interface Finding {
  id: string;
  file_path: string;
  start_line: number;
  end_line: number;
  cwe_id: string | null;
  vulnerability_type: string;
  severity: Severity;
  confidence: number;
  source: string;
  explanation: string;
  code_snippet: string;
  citations: Citation[];
  patch_suggestions?: PatchSuggestion[];
}

export interface ReviewDetail extends ReviewSummary {
  total_cost_usd: number;
  findings: Finding[];
}

export interface AgentLatencyStats {
  agent_name: string;
  run_count: number;
  avg_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
  success_rate: number | null;
}

export interface LatencyStatsResponse {
  per_agent: AgentLatencyStats[];
  total_reviews: number;
  avg_review_latency_ms: number | null;
  total_cost_usd: number;
  cost_tracking_note: string;
}

export interface EvalMetrics {
  n_cases: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  precision: number;
  recall: number;
  f1: number;
  cwe_accuracy_when_detected: number | null;
  total_batch_latency_ms?: number;
  avg_latency_per_file_in_batch_ms?: number;
  classifier_diagnostics?: {
    note: string;
    avg_target_label_score_when_vulnerable: number | null;
    avg_target_label_score_when_safe_lookalike: number | null;
    separation: number | null;
    naive_second_opinion_false_positive_rate: number | null;
  };
}

export interface EvalResultFile {
  results: unknown[];
  metrics: EvalMetrics;
}

export type EvalVariant = "bandit_only" | "merged" | "merged_hf" | "bandit_only_hf";

export type EvalLatestResponse = Partial<Record<EvalVariant, EvalResultFile>>;

export interface InstallationSettings {
  id: string;
  account_login: string;
  notify_on_findings: boolean;
  notify_email: string | null;
}

export interface RepositorySettings {
  id: string;
  full_name: string;
  scan_enabled: boolean;
  auto_patch_enabled: boolean;
  min_severity_to_report: Severity;
}

export interface Settings {
  installations: InstallationSettings[];
  repositories: RepositorySettings[];
}

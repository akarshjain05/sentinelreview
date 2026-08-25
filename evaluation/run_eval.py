"""
Runs the real Bandit analyzer against evaluation/fixtures/python_vuln_benchmark.py
and computes precision/recall/F1 against hand-labeled ground truth.

This is a real, reproducible measurement -- run it yourself:
    PYTHONPATH=backend python3 evaluation/run_eval.py

Scope honestly stated: 17 hand-written cases (10 vulnerable, 7 safe) is
enough to sanity-check the pipeline isn't trivially broken and to produce a
real, non-fabricated metric for a resume bullet -- it is NOT a substitute
for a large, adversarially-constructed benchmark like OWASP Benchmark. That
remains a documented next step (see README).

CLASSIFIER DESIGN (v2, corroboration-only): an earlier version used the
zero-shot classifier as an independent second opinion -- if it was
confident about ANY label on a case Bandit missed, that flipped the case to
"vulnerable". Run for real against facebook/bart-large-mnli, that dropped
precision from 0.900 to 0.714 (four new false positives, including an 84%-
confidence "SSRF" call on a trivial cache class). Root cause, found in the
raw scores: a true catch and a false positive scored 0.62 and 0.61 on the
SAME label -- the model isn't discriminating these cases at all.

This version never lets the classifier change predicted_vulnerable --
Bandit alone still decides that, so precision/recall/F1 with --use-hf are
IDENTICAL to Bandit-alone by construction, not coincidence. The classifier
is instead evaluated on a more honest, targeted question it's actually
suited to answer: "how much does the model's confidence in the SPECIFIC
correct label separate vulnerable code from safe code that superficially
resembles it?" -- see avg_target_score_vulnerable vs
avg_target_score_safe_lookalikes in the metrics output, and
naive_second_opinion_false_positive_rate, which reconstructs what the old
(rejected) design's false-positive rate would have been, quantified against
whatever real classifier you run this with.
"""
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent))

from fixtures.python_vuln_benchmark import BENCHMARK_CASES  # noqa: E402

from app.agents.graph import CWE_CANDIDATE_LABELS
from app.services.static_analysis import merge_analyzer_findings  # noqa: E402
from app.sandbox.analyzers import BanditAnalyzer, SemgrepAnalyzer  # noqa: E402


@dataclass
class CaseResult:
    id: str
    category: str
    ground_truth_vulnerable: bool
    predicted_vulnerable: bool
    ground_truth_cwe: str | None
    predicted_cwes: list[str]
    cwe_match: bool | None  # None if not applicable (both non-vulnerable)
    correct: bool
    # Diagnostic-only classifier fields below -- NONE of these feed back
    # into predicted_vulnerable. They exist to measure whether the
    # classifier's confidence is actually informative, not to make
    # detection decisions with it.
    target_label: str | None = None       # the label matching this case's own category, if any
    target_label_score: float | None = None
    max_label: str | None = None          # whichever label scored highest overall
    max_label_score: float | None = None


def run_bandit_eval(zero_shot=None, use_semgrep: bool = True) -> tuple[list[CaseResult], dict]:
    """
    zero_shot: optional ZeroShotClassifier (e.g. HFZeroShotClassifier).
    When provided, its output is recorded as a diagnostic alongside each
    case but NEVER changes predicted_vulnerable -- see module docstring for
    why an earlier design that did so made results worse, not better.

    use_semgrep: when True (default), runs both BanditAnalyzer and
    SemgrepAnalyzer and merges their findings via the exact same
    merge_analyzer_findings function app/agents/graph.py uses in
    production -- this eval measures what's actually shipped, not just one
    analyzer in isolation. Set False to reproduce the original Bandit-only
    baseline for comparison.
    """
    analyzers = {"bandit": BanditAnalyzer()}
    if use_semgrep:
        analyzers["semgrep"] = SemgrepAnalyzer()

    # This is the same batching fix applied to the production pipeline
    # (app/agents/graph.py's static_analysis_node): ONE subprocess call per
    # analyzer for all 17 cases, not 17 separate calls. Real, measured
    # speedup of ~4.6-5x per analyzer (see README) applies here too --
    # this also makes the eval harness itself much faster to iterate on.
    case_files = {f"{case.id}.py": case.code for case in BENCHMARK_CASES}

    start = time.perf_counter()
    raw_by_analyzer: list[tuple[str, str, object]] = []
    for analyzer_name, analyzer in analyzers.items():
        results_by_case = analyzer.analyze_files(case_files)
        for case_id, raw_findings in results_by_case.items():
            for rf in raw_findings:
                raw_by_analyzer.append((analyzer_name, case_id, rf))
    total_batch_latency_ms = (time.perf_counter() - start) * 1000

    merged = merge_analyzer_findings(raw_by_analyzer)
    merged_by_case: dict[str, list] = {f"{case.id}.py": [] for case in BENCHMARK_CASES}
    for case_id, rf, analyzer_names in merged:
        merged_by_case[case_id].append((rf, analyzer_names))

    results: list[CaseResult] = []

    for case in BENCHMARK_CASES:
        case_merged = merged_by_case[f"{case.id}.py"]
        predicted_vulnerable = len(case_merged) > 0
        predicted_cwes = sorted({rf.cwe_id for rf, _analyzers in case_merged if rf.cwe_id})

        target_label, target_label_score = None, None
        max_label, max_label_score = None, None
        if zero_shot is not None:
            classifications, _, _ = zero_shot.classify(case.code, CWE_CANDIDATE_LABELS)
            if classifications:
                scores_by_label = {c.label: c.score for c in classifications}
                # case.category conveniently already matches the candidate
                # label naming scheme (see fixtures/python_vuln_benchmark.py)
                # except for the "none" category used by generic safe cases.
                if case.category in scores_by_label:
                    target_label = case.category
                    target_label_score = scores_by_label[case.category]
                top = max(classifications, key=lambda c: c.score)
                max_label, max_label_score = top.label, top.score

        cwe_match = None
        if case.vulnerable and predicted_vulnerable:
            cwe_match = case.expected_cwe in predicted_cwes

        correct = predicted_vulnerable == case.vulnerable

        results.append(
            CaseResult(
                id=case.id,
                category=case.category,
                ground_truth_vulnerable=case.vulnerable,
                predicted_vulnerable=predicted_vulnerable,
                ground_truth_cwe=case.expected_cwe,
                predicted_cwes=predicted_cwes,
                cwe_match=cwe_match,
                correct=correct,
                target_label=target_label,
                target_label_score=target_label_score,
                max_label=max_label,
                max_label_score=max_label_score,
            )
        )

    metrics = _compute_metrics(results, total_batch_latency_ms)
    return results, metrics


def _compute_metrics(results: list[CaseResult], total_batch_latency_ms: float) -> dict:
    tp = sum(1 for r in results if r.ground_truth_vulnerable and r.predicted_vulnerable)
    fp = sum(1 for r in results if not r.ground_truth_vulnerable and r.predicted_vulnerable)
    fn = sum(1 for r in results if r.ground_truth_vulnerable and not r.predicted_vulnerable)
    tn = sum(1 for r in results if not r.ground_truth_vulnerable and not r.predicted_vulnerable)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    cwe_applicable = [r for r in results if r.cwe_match is not None]
    cwe_accuracy = (
        sum(1 for r in cwe_applicable if r.cwe_match) / len(cwe_applicable)
        if cwe_applicable else None
    )

    metrics = {
        "n_cases": len(results),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "cwe_accuracy_when_detected": round(cwe_accuracy, 3) if cwe_accuracy is not None else None,
        # NOTE: this is now a single batched call across all n_cases files
        # (one subprocess per analyzer total, not one per file -- see the
        # batching fix in README.md), so "per-file" is an average over the
        # batch, not an independently-measured per-call latency the way it
        # was before. avg_latency_per_file_in_batch_ms divides the one real
        # total_batch_latency_ms by n_cases for a rough per-file sense; it
        # is NOT the same thing as timing n_cases separate subprocess
        # calls, and will be systematically lower than that would be.
        "total_batch_latency_ms": round(total_batch_latency_ms, 2),
        "avg_latency_per_file_in_batch_ms": round(total_batch_latency_ms / len(results), 2) if results else 0.0,
    }

    classifier_results = [r for r in results if r.target_label_score is not None]
    if classifier_results:
        vulnerable_scores = [r.target_label_score for r in classifier_results if r.ground_truth_vulnerable]
        safe_scores = [r.target_label_score for r in classifier_results if not r.ground_truth_vulnerable]

        # Reconstructs what the REJECTED naive-second-opinion design's false
        # positive rate would have been (any label >= 0.5 on a safe case),
        # quantified against whatever real classifier this is run with --
        # this is what justifies not using that design, with a number
        # instead of just an anecdote.
        safe_cases = [r for r in results if not r.ground_truth_vulnerable and r.max_label_score is not None]
        naive_fp_rate = (
            sum(1 for r in safe_cases if r.max_label_score >= 0.5) / len(safe_cases)
            if safe_cases else None
        )

        metrics["classifier_diagnostics"] = {
            "note": "None of these affect precision/recall/f1 above -- diagnostic only, see module docstring.",
            "avg_target_label_score_when_vulnerable": round(sum(vulnerable_scores) / len(vulnerable_scores), 3) if vulnerable_scores else None,
            "avg_target_label_score_when_safe_lookalike": round(sum(safe_scores) / len(safe_scores), 3) if safe_scores else None,
            "separation": (
                round(sum(vulnerable_scores) / len(vulnerable_scores) - sum(safe_scores) / len(safe_scores), 3)
                if vulnerable_scores and safe_scores else None
            ),
            "naive_second_opinion_false_positive_rate": round(naive_fp_rate, 3) if naive_fp_rate is not None else None,
        }

    return metrics


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run the SentinelReview eval harness")
    parser.add_argument(
        "--use-hf", action="store_true",
        help="Also run the real HFZeroShotClassifier (facebook/bart-large-mnli) as a "
             "diagnostic alongside detection (does NOT change detection decisions -- see "
             "module docstring for why). Requires 'pip install transformers torch' and "
             "network access to huggingface.co to download the model on first use.",
    )
    parser.add_argument(
        "--bandit-only", action="store_true",
        help="Run Bandit alone, without Semgrep, to reproduce the original single-analyzer "
             "baseline for comparison. Default runs both (merged), matching what's actually "
             "shipped in app/agents/graph.py.",
    )
    args = parser.parse_args()

    zero_shot = None
    if args.use_hf:
        from app.agents.hf_classifier import HFZeroShotClassifier
        try:
            print("Loading facebook/bart-large-mnli (downloads ~1.6GB on first run)...")
            zero_shot = HFZeroShotClassifier()
        except ImportError as e:
            print(f"ERROR: {e}")
            return

    results, metrics = run_bandit_eval(zero_shot=zero_shot, use_semgrep=not args.bandit_only)

    print("=" * 70)
    analyzer_label = "Bandit only" if args.bandit_only else "Bandit + Semgrep (merged)"
    label = f"{analyzer_label} + HF classifier diagnostics" if zero_shot else analyzer_label
    print(f"SentinelReview Eval: {label} vs. hand-labeled benchmark")
    print("=" * 70)
    for r in results:
        status = "✅" if r.correct else "❌"
        cwe_note = ""
        if r.ground_truth_vulnerable:
            cwe_note = f" expected={r.ground_truth_cwe} got={r.predicted_cwes}"
        clf_note = ""
        if r.target_label_score is not None:
            clf_note = f" | target({r.target_label})={r.target_label_score:.2f} max({r.max_label})={r.max_label_score:.2f}"
        print(f"{status} {r.id:20s} {r.category:22s} vuln={r.predicted_vulnerable!s:5} (truth={r.ground_truth_vulnerable!s:5}){cwe_note}{clf_note}")

    print("-" * 70)
    print(json.dumps(metrics, indent=2))

    suffix = ("bandit_only" if args.bandit_only else "merged") + ("_hf" if zero_shot else "")
    out_path = Path(__file__).parent / f"results_{suffix}.json"
    out_path.write_text(json.dumps({"results": [asdict(r) for r in results], "metrics": metrics}, indent=2))
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()

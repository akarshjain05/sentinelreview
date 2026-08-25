"""
The SentinelReview LangGraph pipeline.

Graph shape:

    triage -> static_analysis -> retrieval -> classification -> fix_suggestion
                                                                       |
                                                                       v
                                                                 verification
                                                                       |
                                                                       v
                                                                  reporting -> END

Each node is a pure function `(ReviewState) -> dict` returning only the keys
it updates (LangGraph merges this into state). Nodes never mutate shared
state directly and never call tools outside their own allowlist
(enforced via `assert_tool_allowed`).
"""
from __future__ import annotations

from langgraph.graph import END, StateGraph

from app.agents.diff_utils import extract_added_lines
from app.agents.model_clients import (
    GenerationClient,
    LiteLLMClassifier,
    LiteLLMClient,
    MockGenerationClient,
    MockZeroShotClassifier,
    ZeroShotClassifier,
)
from app.agents.state import (
    Finding,
    KnowledgeSnippet,
    PatchSuggestion,
    ReviewState,
    SecurityFlag,
    VerificationOutcome,
)
from app.core.config import get_settings
from app.knowledge.tfidf_index import TfidfKnowledgeIndex
from app.sandbox.analyzers import (
    BanditAnalyzer,
    RawFinding,
    SemgrepAnalyzer,
    StaticAnalyzer,
)
from app.security.guardrails import assert_tool_allowed, sanitize_untrusted_text

CWE_CANDIDATE_LABELS = [
    "sql_injection", "xss", "ssrf", "command_injection", "unsafe_eval",
    "unsafe_deserialization", "path_traversal", "hardcoded_secret",
    "weak_cryptography", "idor", "auth_bypass",
]

# Maps a finding's CWE ID to the specific candidate label that actually
# corresponds to it. This is the single source of truth used by
# classification_node to look up the classifier's confidence for the ONE
# label that matters for a given finding -- not whichever label happens to
# score highest across all 11 candidates (see the "HF classifier finding"
# section in README.md: taking the argmax across unrelated categories is
# what produced a 84%-confidence "SSRF" false positive on a trivial cache
# class, and is exactly the bug this mapping exists to prevent).
LABEL_TO_CWE = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "command_injection": "CWE-78",
    "unsafe_eval": "CWE-95",
    "unsafe_deserialization": "CWE-502",
    "path_traversal": "CWE-22",
    "hardcoded_secret": "CWE-798",
    "weak_cryptography": "CWE-327",
    # idor/auth_bypass are OWASP categories Bandit has no corresponding CWE
    # check for, so there's no static-analyzer finding to corroborate them
    # against -- intentionally left unmapped rather than guessed.
}
CWE_TO_LABEL = {cwe: label for label, cwe in LABEL_TO_CWE.items()}

# How close two findings' line numbers need to be to count as "the same
# underlying issue" reported by different analyzers. Bandit and Semgrep
# don't always agree on the exact line (e.g. Bandit may point at the
# .execute( call while a Semgrep pattern spans the whole statement) -- a
# small window catches the common case without merging genuinely distinct
# findings that happen to share a CWE elsewhere in the same file.
_LINE_PROXIMITY_THRESHOLD = 2


def merge_analyzer_findings(
    findings_by_analyzer: list[tuple[str, str, RawFinding]],
) -> list[tuple[str, RawFinding, list[str]]]:
    """
    Merges RawFindings from multiple analyzers that agree on the same
    underlying issue (same file, same CWE, nearby lines) into one entry,
    tracking which analyzer(s) reported it. Findings with no CWE mapping,
    or that don't overlap with any finding from another analyzer, pass
    through unchanged.

    Input: list of (analyzer_name, file_path, RawFinding) tuples.
    Output: list of (file_path, RawFinding, [analyzer_names]) tuples, where
    the RawFinding is the first one seen for that merged group (arbitrary
    but deterministic choice among agreeing findings) and analyzer_names
    lists every analyzer that reported it.

    This exists so running Bandit + Semgrep together produces ONE finding
    per real vulnerability in the PR review comment, not two -- duplicate
    findings for something both tools agree on would look like noise to
    whoever's reading the review, undermining trust in the tool more than
    the extra coverage from a second analyzer is worth.
    """
    # Group candidates by (file_path, cwe_id) -- only findings that share
    # both can possibly be "the same issue".
    groups: dict[tuple[str, str], list[tuple[str, RawFinding]]] = {}
    unmatchable: list[tuple[str, RawFinding, list[str]]] = []

    for analyzer_name, file_path, rf in findings_by_analyzer:
        if rf.cwe_id is None:
            unmatchable.append((file_path, rf, [analyzer_name]))
            continue
        groups.setdefault((file_path, rf.cwe_id), []).append((analyzer_name, rf))

    merged: list[tuple[str, RawFinding, list[str]]] = []
    for (file_path, _cwe), candidates in groups.items():
        # Greedily cluster by line proximity within this (file, cwe) group.
        candidates_sorted = sorted(candidates, key=lambda pair: pair[1].start_line)
        cluster: list[tuple[str, RawFinding]] = []
        for analyzer_name, rf in candidates_sorted:
            if cluster and rf.start_line - cluster[-1][1].start_line > _LINE_PROXIMITY_THRESHOLD:
                # Close out the previous cluster, start a new one.
                rep_analyzer, rep_finding = cluster[0]
                merged.append((file_path, rep_finding, [a for a, _ in cluster]))
                cluster = []
            cluster.append((analyzer_name, rf))
        if cluster:
            rep_analyzer, rep_finding = cluster[0]
            merged.append((file_path, rep_finding, [a for a, _ in cluster]))

    return merged + unmatchable


def build_graph(
    *,
    zero_shot: ZeroShotClassifier | None = None,
    static_analyzers: dict[str, StaticAnalyzer] | None = None,
    knowledge_index: TfidfKnowledgeIndex | None = None,
    generator: GenerationClient | None = None,
    max_retries: int = 2,
):
    """
    Build the compiled LangGraph pipeline.

    static_analyzers defaults to REAL Bandit + Semgrep CLI wrappers
    (app.sandbox.analyzers.BanditAnalyzer, SemgrepAnalyzer) -- actual static
    analysis from two genuinely independent tools (AST-visitor checks vs.
    pattern matching against a hand-written local ruleset), not a
    simulation. Findings both tools agree on (same file, same CWE, nearby
    lines) are merged into one Finding with source="bandit+semgrep" rather
    than reported twice -- see _merge_analyzer_findings. knowledge_index
    defaults to a real TF-IDF retrieval index over the curated seed corpus
    (app.knowledge.seed_corpus) -- actual classical IR, not a hash stand-in.

    zero_shot and generator remain mocked: this environment cannot reach
    huggingface.co or an LLM API, so there is no honest way to make those
    real here. Both are injectable Protocols specifically so a real
    HFInferenceClient / AnthropicLLMClient can be dropped in without
    touching any node logic.
    """
    settings = get_settings()
    if settings.openai_api_key or settings.anthropic_api_key or settings.gemini_api_key or settings.groq_api_key or settings.nvidia_api_key:
        if settings.nvidia_api_key:
            model = "nvidia_nim/meta/llama-3.1-70b-instruct"
        elif settings.openai_api_key:
            model = "gpt-4o-mini"
        elif settings.anthropic_api_key:
            model = "claude-3-5-sonnet-20240620"
        elif settings.groq_api_key:
            model = "groq/qwen/qwen3.6-27b"
        else:
            model = "gemini/gemini-flash-latest" 
            
        zero_shot = zero_shot or LiteLLMClassifier(model=model)
        generator = generator or LiteLLMClient(model=model)
    else:
        zero_shot = zero_shot or MockZeroShotClassifier()
        generator = generator or MockGenerationClient()
        
    static_analyzers = static_analyzers or {"bandit": BanditAnalyzer(), "semgrep": SemgrepAnalyzer()}
    knowledge_index = knowledge_index or TfidfKnowledgeIndex.from_seed_corpus()

    # ---- Node implementations -------------------------------------------------

    def triage_node(state: ReviewState) -> dict:
        assert_tool_allowed("triage", "list_changed_files")
        sanitized_title = sanitize_untrusted_text(state.pr_title, source="pr_title")
        sanitized_body = sanitize_untrusted_text(state.pr_body, source="pr_body")
        new_flags = list(state.security_flags)
        for result in (sanitized_title, sanitized_body):
            if result.flagged:
                new_flags.append(SecurityFlag(source="pr_metadata", matched_patterns=result.matched_patterns))

        files_to_review, skipped = [], []
        for f in state.changed_files:
            if f.is_doc_file:
                skipped.append(f.path)
                continue
            files_to_review.append(f.path)

        return {"files_to_review": files_to_review, "skipped_files": skipped, "security_flags": new_flags}

    def static_analysis_node(state: ReviewState) -> dict:
        assert_tool_allowed("static_analysis", "run_semgrep")
        assert_tool_allowed("static_analysis", "run_bandit")

        review_set = set(state.files_to_review)
        files_to_scan: dict[str, str] = {}  # file_path -> extracted source

        for f in state.changed_files:
            if f.path not in review_set:
                continue
            sanitize_untrusted_text(f.diff, source=f"diff:{f.path}")  # flags injection attempts; diff itself still analyzed as code

            if not f.path.endswith(".py"):
                continue  # both analyzers are Python-specific; other languages need a different analyzer (future work)

            files_to_scan[f.path] = extract_added_lines(f.diff)

        # This is the actual fix for the latency finding documented in
        # README.md: ONE subprocess call per analyzer for the whole PR,
        # not one call per file. Measured real speedup on a 5-file batch,
        # with proper warm-up + repeated trials (a first hasty single-trial
        # measurement misleadingly showed Bandit batching as a *regression*
        # -- wrong, corrected by re-testing properly rather than trusting
        # one noisy sample): Semgrep ~4.8-5x (2.8s vs 13.5-14s), Bandit
        # ~4.6-5x (0.21s vs 1.0s). Both analyzers benefit consistently once
        # measured correctly.
        raw_by_analyzer: list[tuple[str, str, RawFinding]] = []  # (analyzer_name, file_path, RawFinding)
        if files_to_scan:
            for analyzer_name, analyzer in static_analyzers.items():
                try:
                    results_by_file = analyzer.analyze_files(files_to_scan)
                except Exception as e:
                    results_by_file = {}
                    # In production this would be logged to AgentRun.error_message, not swallowed silently.
                    _ = e
                for file_path, raw_findings in results_by_file.items():
                    for rf in raw_findings:
                        raw_by_analyzer.append((analyzer_name, file_path, rf))

        merged = merge_analyzer_findings(raw_by_analyzer)

        findings: list[Finding] = []
        for file_path, rf, analyzer_names in merged:
            findings.append(
                Finding(
                    file_path=file_path,
                    start_line=rf.start_line,
                    end_line=rf.end_line,
                    vulnerability_type=rf.cwe_id or rf.test_id,
                    cwe_id=rf.cwe_id,
                    confidence={"LOW": 0.4, "MEDIUM": 0.7, "HIGH": 0.9}.get(rf.confidence, 0.5),
                    source="+".join(sorted(set(analyzer_names))),
                    code_snippet=rf.code_snippet,
                    explanation=rf.message,
                )
            )
        return {"raw_analyzer_findings": findings}

    def retrieval_node(state: ReviewState) -> dict:
        assert_tool_allowed("retrieval", "hybrid_search")
        assert_tool_allowed("retrieval", "rerank")

        if not state.raw_analyzer_findings:
            return {"retrieved_knowledge": []}

        # Real TF-IDF + cosine similarity search per finding, deduplicated
        # by document. In production this becomes hybrid BM25 + pgvector
        # cosine search against the live NVD/OSV/GHSA/OWASP corpus, behind
        # the exact same TfidfKnowledgeIndex.search() interface.
        seen_doc_ids: set[str] = set()
        snippets: list[KnowledgeSnippet] = []
        for finding in state.raw_analyzer_findings:
            query = f"{finding.vulnerability_type} {finding.explanation} {finding.code_snippet}"
            for result in knowledge_index.search(query, top_k=2):
                if result.document.document_id in seen_doc_ids:
                    continue
                seen_doc_ids.add(result.document.document_id)
                snippets.append(
                    KnowledgeSnippet(
                        document_id=result.document.document_id,
                        source=result.document.source,
                        title=result.document.title,
                        text=result.document.text,
                        url=result.document.url,
                        relevance_score=result.score,
                    )
                )
        snippets.sort(key=lambda s: s.relevance_score, reverse=True)
        return {"retrieved_knowledge": snippets}

    def classification_node(state: ReviewState) -> dict:
        assert_tool_allowed("classification", "zero_shot_classify")
        assert_tool_allowed("classification", "token_classify")

        refined: list[Finding] = []
        total_tokens = 0
        total_cost = 0.0
        for finding in state.raw_analyzer_findings:
            classifications, tokens, cost = zero_shot.classify(finding.code_snippet, CWE_CANDIDATE_LABELS)
            total_tokens += tokens
            total_cost += cost
            scores_by_label = {c.label: c.score for c in classifications}

            # This is the fix: look up the classifier's confidence for the
            # ONE label that actually corresponds to this finding's CWE, not
            # whichever of the 11 candidate labels happened to score
            # highest overall. Taking the argmax across unrelated categories
            # is what produced a real 84%-confidence "SSRF" false positive
            # on a trivial cache class during evaluation (see README) --
            # confidently asserting an irrelevant label is worse than not
            # corroborating at all.
            target_label = CWE_TO_LABEL.get(finding.cwe_id)  # type: ignore
            target_score = scores_by_label.get(target_label) if target_label else None

            cited = [s.document_id for s in state.retrieved_knowledge if s.document_id == finding.cwe_id]

            if target_score is not None and target_score >= 0.7:
                severity = "high"
                corroboration_note = (
                    f"Classifier corroborates with {target_score:.2f} confidence "
                    f"on the matching label '{target_label}'."
                )
            elif target_score is not None:
                severity = "medium"
                corroboration_note = (
                    f"Classifier assigned {target_score:.2f} confidence to the matching "
                    f"label '{target_label}' (below high-confidence threshold)."
                )
            else:
                severity = "medium"
                corroboration_note = (
                    "No corresponding classifier label to corroborate this finding type; "
                    "severity based on static analyzer confidence alone."
                )

            explanation = (
                f"Detected pattern consistent with {finding.vulnerability_type} "
                f"(static analyzer confidence {finding.confidence:.2f}). {corroboration_note}"
            )
            refined.append(
                finding.model_copy(
                    update={
                        "severity": severity,
                        # Preserve which analyzer(s) actually found this
                        # (e.g. "bandit+semgrep" when both agree) rather
                        # than clobbering it with a generic "combined" --
                        # agreement between two independent analyzers is a
                        # real, meaningful confidence signal that a blanket
                        # label would throw away.
                        "source": f"{finding.source}+classifier",
                        "explanation": explanation,
                        "cited_document_ids": cited,
                    }
                )
            )
        return {"findings": refined, "tokens_used": total_tokens, "cost_usd": total_cost}

    def fix_suggestion_node(state: ReviewState) -> dict:
        assert_tool_allowed("fix_suggestion", "generate_patch")

        import re
        suggestions: list[PatchSuggestion] = []
        total_tokens = 0
        total_cost = 0.0
        for idx, finding in enumerate(state.findings):
            if not finding.cited_document_ids:
                # Guardrail: never generate a fix that isn't grounded in at
                # least one retrieved authoritative source.
                continue
            citation_context = "\n".join(
                s.text for s in state.retrieved_knowledge if s.document_id in finding.cited_document_ids
            )
            
            # Find the original file content
            original_file = next((f for f in state.changed_files if f.path == finding.file_path), None)
            file_content = original_file.diff if original_file else "(file content unavailable)"
            
            result = generator.generate(
                system_prompt=(
                    "You are a security patch generator. Only suggest fixes grounded in the "
                    "provided reference material. Never invent vulnerabilities or citations.\n"
                    "Provide the complete patched file content enclosed in <patched_file> tags."
                ),
                user_content=f"Finding: {finding.explanation}\nReferences:\n{citation_context}\n\nFile ({finding.file_path}):\n{file_content}",
            )
            total_tokens += result.tokens
            total_cost += result.cost
            
            # Extract patched file content
            patched_content = ""
            reasoning = result.content
            match = re.search(r"<patched_file>\s*(.*?)\s*</patched_file>", result.content, re.DOTALL)
            if match:
                patched_content = match.group(1)
                reasoning = result.content.replace(match.group(0), "").strip()
                # Remove prefixes like "Explanation:" or "Reasoning:" if they exist at the start
                reasoning = re.sub(r"^(Explanation|Reasoning):\s*", "", reasoning, flags=re.IGNORECASE).strip()
            else:
                patched_content = result.content
            
            suggestions.append(
                PatchSuggestion(
                    finding_index=idx,
                    diff=patched_content,
                    reasoning=reasoning,
                    cited_document_ids=finding.cited_document_ids,
                )
            )
        return {"patch_suggestions": suggestions, "tokens_used": total_tokens, "cost_usd": total_cost}

    def verification_node(state: ReviewState) -> dict:
        assert_tool_allowed("verification", "apply_patch_sandboxed")

        outcomes: list[VerificationOutcome] = []
        for idx, patch in enumerate(state.patch_suggestions):
            finding = state.findings[patch.finding_index]
            
            # Use real static analyzers to verify the patch
            patched_code = patch.diff
            
            issue_resolved = True
            introduced_new_findings = False
            log_output = ""
            
            # Re-run static analyzers on the patched code
            for analyzer_name, analyzer in static_analyzers.items():
                try:
                    results = analyzer.analyze_file(finding.file_path, patched_code)
                    if results:
                        # Found findings in the patched file
                        # Check if the same finding still exists
                        same_finding = any(rf.cwe_id == finding.cwe_id for rf in results)
                        if same_finding:
                            issue_resolved = False
                            log_output += f"{analyzer_name} still found {finding.cwe_id} in patched code.\n"
                        else:
                            introduced_new_findings = True
                            log_output += f"{analyzer_name} found new issues in patched code.\n"
                except Exception as e:
                    issue_resolved = False
                    log_output += f"Analyzer {analyzer_name} failed: {e}\n"
            
            outcomes.append(
                VerificationOutcome(
                    patch_index=idx,
                    issue_resolved=issue_resolved,
                    tests_passed=False,  # Sandboxed execution not yet implemented
                    build_succeeded=False, # Sandboxed build not yet implemented
                    introduced_new_findings=introduced_new_findings,
                    log=log_output or "Static verification passed. Dynamic sandboxed verification not yet implemented.",
                )
            )
        return {"verification_outcomes": outcomes}

    def reporting_node(state: ReviewState) -> dict:
        assert_tool_allowed("reporting", "format_review_comment")

        lines = ["## SentinelReview — Automated Security Review\n"]
        if not state.findings:
            lines.append("No security findings detected in the reviewed files.")
        for i, finding in enumerate(state.findings):
            verified = next(
                (v for v in state.verification_outcomes
                 if any(p.finding_index == i for p in [state.patch_suggestions[v.patch_index]] if v.patch_index < len(state.patch_suggestions))),
                None,
            )
            lines.append(f"### {finding.severity.upper()}: {finding.vulnerability_type} in `{finding.file_path}`")
            lines.append(f"Lines {finding.start_line}-{finding.end_line} | Confidence: {finding.confidence:.2f}")
            lines.append(finding.explanation)
            if finding.cited_document_ids:
                lines.append(f"References: {', '.join(finding.cited_document_ids)}")
            if verified and verified.is_safe_to_suggest:
                lines.append("✅ A verified patch is available.")
            lines.append("")
        if state.security_flags:
            lines.append("---")
            lines.append(
                f"⚠️ {len(state.security_flags)} suspicious pattern(s) detected in PR metadata/content "
                "and were isolated as untrusted data rather than followed as instructions."
            )
        return {"review_markdown": "\n".join(lines)}

    # ---- Graph wiring -----------------------------------------------------

    graph = StateGraph(ReviewState)
    graph.add_node("triage", triage_node)
    graph.add_node("static_analysis", static_analysis_node)
    graph.add_node("retrieval", retrieval_node)
    graph.add_node("classification", classification_node)
    graph.add_node("fix_suggestion", fix_suggestion_node)
    graph.add_node("verification", verification_node)
    graph.add_node("reporting", reporting_node)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "static_analysis")
    graph.add_edge("static_analysis", "retrieval")
    graph.add_edge("retrieval", "classification")
    graph.add_edge("classification", "fix_suggestion")
    graph.add_edge("fix_suggestion", "verification")
    graph.add_edge("verification", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()

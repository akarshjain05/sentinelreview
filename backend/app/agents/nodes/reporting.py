from app.agents.state import ReviewState
from app.agents.tools import assert_tool_allowed

def reporting_node(state: ReviewState) -> dict:
    assert_tool_allowed("reporting", "format_review_comment")

    lines = ["## SentinelReview — Automated Security Review\n"]
    if not state.findings:
        lines.append("No security findings detected in the reviewed files.")
    outcomes_by_finding = {
        state.patch_suggestions[v.patch_index].finding_index: v
        for v in state.verification_outcomes
        if v.patch_index < len(state.patch_suggestions)
    }

    for i, finding in enumerate(state.findings):
        verified = outcomes_by_finding.get(i)
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

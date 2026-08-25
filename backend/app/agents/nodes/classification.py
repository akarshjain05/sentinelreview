from app.agents.state import ReviewState, PipelineFinding
from app.security.guardrails import assert_tool_allowed

CWE_CANDIDATE_LABELS = [
    "sql_injection", "xss", "ssrf", "command_injection", "unsafe_eval",
    "unsafe_deserialization", "path_traversal", "hardcoded_secret",
    "weak_cryptography", "idor", "auth_bypass",
]

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
}
CWE_TO_LABEL = {cwe: label for label, cwe in LABEL_TO_CWE.items()}

def make_classification_node(zero_shot):
    def classification_node(state: ReviewState) -> dict:
        assert_tool_allowed("classification", "zero_shot_classify")
        assert_tool_allowed("classification", "token_classify")

        refined: list[PipelineFinding] = []
        total_tokens = 0
        total_cost = 0.0
        
        for finding in state.findings:
            classifications, tokens, cost = zero_shot.classify(finding.code_snippet, CWE_CANDIDATE_LABELS)
            total_tokens += tokens
            total_cost += cost
            scores_by_label = {c.label: c.score for c in classifications}

            target_label = CWE_TO_LABEL.get(finding.cwe_id)
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
                        "source": f"{finding.source}+classifier",
                        "explanation": explanation,
                        "cited_document_ids": cited,
                    }
                )
            )
            
        return {"findings": refined, "tokens_used": total_tokens, "cost_usd": total_cost}
    return classification_node

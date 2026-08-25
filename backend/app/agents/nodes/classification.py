import json
from app.agents.state import ReviewState, Severity
from app.agents.tools import assert_tool_allowed

def make_classification_node(classifier):
    def classification_node(state: ReviewState) -> dict:
        assert_tool_allowed("classification", "classify_finding")
        refined = []
        total_tokens = 0
        total_cost = 0.0
        
        for finding in state.findings:
            context = "\n".join(s.text for s in state.retrieved_knowledge)
            prompt = (
                f"Finding: {finding.explanation}\n"
                f"Code: {finding.code_snippet}\n"
                f"Context: {context}\n"
                "Return JSON with 'severity' (CRITICAL, HIGH, MEDIUM, LOW, INFO), "
                "'explanation', and 'cited_document_ids' (array of strings, ONLY from the Context provided above)."
            )
            result = classifier.generate(
                system_prompt="You are a security classifier. Output exactly the requested JSON, nothing else.",
                user_content=prompt,
            )
            total_tokens += result.tokens
            total_cost += result.cost
            
            try:
                parsed = json.loads(result.content)
                severity = Severity(parsed["severity"].lower())
                explanation = parsed["explanation"]
                cited = parsed.get("cited_document_ids", [])
            except (json.JSONDecodeError, KeyError, ValueError):
                severity = finding.severity
                explanation = finding.explanation
                cited = []

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

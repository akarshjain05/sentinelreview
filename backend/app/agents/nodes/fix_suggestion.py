import re
from app.agents.state import ReviewState, PatchSuggestion
from app.agents.tools import assert_tool_allowed

def make_fix_suggestion_node(generator):
    def fix_suggestion_node(state: ReviewState) -> dict:
        assert_tool_allowed("fix_suggestion", "generate_patch")

        suggestions: list[PatchSuggestion] = []
        total_tokens = 0
        total_cost = 0.0
        for idx, finding in enumerate(state.findings):
            if not finding.cited_document_ids:
                continue
            citation_context = "\n".join(
                s.text for s in state.retrieved_knowledge if s.document_id in finding.cited_document_ids
            )
            
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
            
            patched_content = ""
            reasoning = result.content
            match = re.search(r"<patched_file>\s*(.*?)\s*</patched_file>", result.content, re.DOTALL)
            if match:
                patched_content = match.group(1)
                reasoning = result.content.replace(match.group(0), "").strip()
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
    return fix_suggestion_node

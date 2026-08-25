from app.agents.state import KnowledgeSnippet, ReviewState
from app.security.guardrails import assert_tool_allowed


def make_retrieval_node(knowledge_index):
    def retrieval_node(state: ReviewState) -> dict:
        assert_tool_allowed("retrieval", "hybrid_search")
        results = []
        seen = set()
        for finding in state.findings:
            if not finding.cwe_id:
                continue
            query = f"{finding.cwe_id} {finding.vulnerability_type} {finding.explanation}"
            hits = knowledge_index.search(query, top_k=2)
            for h in hits:
                doc_id = h.document.document_id
                if doc_id not in seen:
                    seen.add(doc_id)
                    results.append(
                        KnowledgeSnippet(
                            document_id=doc_id,
                            source=h.document.source,
                            title=h.document.title,
                            text=h.document.text,
                            url=h.document.url,
                            relevance_score=h.score,
                        )
                    )
        return {"retrieved_knowledge": results}
    return retrieval_node

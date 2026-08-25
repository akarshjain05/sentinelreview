from app.agents.state import ReviewState, SearchResult
from app.agents.tools import assert_tool_allowed

def make_retrieval_node(knowledge_index):
    def retrieval_node(state: ReviewState) -> dict:
        assert_tool_allowed("retrieval", "search_knowledge_base")
        results = []
        seen = set()
        for finding in state.findings:
            if not finding.cwe_id:
                continue
            query = f"{finding.cwe_id} {finding.vulnerability_type} {finding.explanation}"
            hits = knowledge_index.search(query, k=2)
            for h in hits:
                doc_id = h["document_id"]
                if doc_id not in seen:
                    seen.add(doc_id)
                    results.append(
                        SearchResult(
                            document_id=doc_id,
                            chunk_index=h["chunk_index"],
                            text=h["chunk_text"],
                            score=h["score"],
                        )
                    )
        return {"retrieved_knowledge": results}
    return retrieval_node

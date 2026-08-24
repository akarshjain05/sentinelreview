"""
Real TF-IDF + cosine similarity retrieval over the knowledge corpus.

This replaces MockEmbeddingClient/MockReranker's hash-based stand-ins with
an actual classical information-retrieval algorithm: scikit-learn's
TfidfVectorizer + cosine similarity. It is not a neural embedding model
(this environment can't reach huggingface.co to download one), but it is a
real, correct, testable retrieval algorithm -- the same family of technique
that powered production search before dense embeddings, and a legitimate
BM25-adjacent baseline to compare a future neural retriever against.

Swapping this for a real sentence-transformers model later is a drop-in
replacement behind the same `search()` interface.
"""
from __future__ import annotations

from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class IndexedDocument:
    document_id: str
    source: str
    title: str
    text: str
    url: str | None = None


@dataclass
class SearchResult:
    document: IndexedDocument
    score: float


class TfidfKnowledgeIndex:
    """
    In-memory TF-IDF index. For production scale this would persist vectors
    in pgvector (via TruncatedSVD to get a fixed-width dense vector, or by
    swapping in a real neural embedding client) -- but the retrieval
    *interface* (`search`) is identical either way, which is the point.
    """

    def __init__(self, documents: list[IndexedDocument]):
        self._documents = documents
        self._vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        corpus_texts = [f"{d.title}. {d.text}" for d in documents]
        self._matrix = self._vectorizer.fit_transform(corpus_texts) if documents else None

    def search(self, query: str, top_k: int = 5, min_score: float = 0.05) -> list[SearchResult]:
        if not self._documents or self._matrix is None:
            return []

        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix)[0]

        ranked = sorted(zip(self._documents, scores), key=lambda pair: pair[1], reverse=True)
        results = [
            SearchResult(document=doc, score=float(score))
            for doc, score in ranked
            if score >= min_score
        ][:top_k]
        return results

    @classmethod
    def from_seed_corpus(cls) -> TfidfKnowledgeIndex:
        from app.knowledge.seed_corpus import SEED_DOCUMENTS

        docs = [
            IndexedDocument(
                document_id=d["external_id"],
                source=d["source"],
                title=d["title"],
                text=d["content"],
            )
            for d in SEED_DOCUMENTS
        ]
        return cls(docs)

    @classmethod
    def from_db(cls, db, *, include_seed_corpus: bool = True) -> TfidfKnowledgeIndex:
        """
        Build the index from real ingested KnowledgeDocument rows (e.g. live
        GHSA advisories pulled via app/knowledge/ingest_cli.py), optionally
        merged with the curated CWE/OWASP seed corpus -- GHSA advisories are
        about specific package vulnerabilities, while the seed corpus covers
        general vulnerability *classes*, so the two are complementary rather
        than redundant.
        """
        from app.db.models import KnowledgeDocument

        docs = [
            IndexedDocument(
                document_id=row.external_id,
                source=row.source,
                title=row.title,
                text=row.content,
                url=row.url,
            )
            for row in db.query(KnowledgeDocument).all()
        ]

        if include_seed_corpus:
            seed_index = cls.from_seed_corpus()
            existing_ids = {d.document_id for d in docs}
            docs.extend(d for d in seed_index._documents if d.document_id not in existing_ids)

        return cls(docs)

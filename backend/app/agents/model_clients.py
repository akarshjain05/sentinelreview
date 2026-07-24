"""
Swappable model client interfaces.

Every ML-backed capability the agents need is defined as a Protocol here.
Concrete implementations can be:
  - Mock*Client: deterministic, no network calls -- used in unit tests and
    local dev without API keys/GPU
  - HFInferenceClient: calls HuggingFace Inference Endpoints / local
    transformers pipelines for Token Classification, Zero-Shot
    Classification, Feature Extraction, Sentence Similarity, Text Ranking
  - AnthropicLLMClient / OpenAILLMClient: for QA/summarization/fix generation

This indirection is what lets the classification model, the reranker, or the
generation model be swapped later without touching agent logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
import litellm
from litellm import completion, completion_cost

@dataclass
class GenerationResult:
    content: str
    tokens: int
    cost: float


@dataclass
class ClassificationResult:
    label: str  # e.g. CWE-89
    score: float


class ZeroShotClassifier(Protocol):
    def classify(self, text: str, candidate_labels: list[str]) -> tuple[list[ClassificationResult], int, float]: ...


class TokenClassifier(Protocol):
    def find_spans(self, code: str) -> list[tuple[int, int, str, float]]:
        """Returns (start_line, end_line, label, confidence) tuples."""
        ...


class EmbeddingClient(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class Reranker(Protocol):
    def rerank(self, query: str, documents: list[str]) -> list[float]:
        """Returns a relevance score per document, same order as input."""
        ...


class GenerationClient(Protocol):
    def generate(self, system_prompt: str, user_content: str, *, max_tokens: int = 1024) -> GenerationResult: ...


# ---------------------------------------------------------------------------
# Mock implementations -- deterministic, offline, used for tests/local dev.
# ---------------------------------------------------------------------------

_KNOWN_VULN_KEYWORDS = {
    "execute(": ("CWE-89", "sql_injection"),
    "cursor.execute": ("CWE-89", "sql_injection"),
    "innerHTML": ("CWE-79", "xss"),
    "eval(": ("CWE-95", "unsafe_eval"),
    "subprocess.call": ("CWE-78", "command_injection"),
    "os.system": ("CWE-78", "command_injection"),
    "pickle.loads": ("CWE-502", "unsafe_deserialization"),
    "requests.get(url": ("CWE-918", "ssrf"),
}


class MockZeroShotClassifier:
    def classify(self, text: str, candidate_labels: list[str]) -> tuple[list[ClassificationResult], int, float]:
        results = []
        lowered = text.lower()
        for label in candidate_labels:
            score = 0.85 if label.lower().replace("_", " ") in lowered.replace("_", " ") else 0.1
            results.append(ClassificationResult(label=label, score=score))
        return sorted(results, key=lambda r: r.score, reverse=True), 0, 0.0


class MockTokenClassifier:
    def find_spans(self, code: str) -> list[tuple[int, int, str, float]]:
        spans = []
        for i, line in enumerate(code.splitlines(), start=1):
            for keyword, (cwe, _) in _KNOWN_VULN_KEYWORDS.items():
                if keyword in line:
                    spans.append((i, i, cwe, 0.9))
        return spans


class MockEmbeddingClient:
    def embed(self, texts: list[str]) -> list[list[float]]:
        # Deterministic pseudo-embedding via character codes, purely for
        # exercising the retrieval pipeline shape in tests -- not semantically meaningful.
        return [[float(sum(ord(c) for c in t) % 997) / 997.0] * 8 for t in texts]


class MockReranker:
    def rerank(self, query: str, documents: list[str]) -> list[float]:
        query_words = set(query.lower().split())
        scores = []
        for doc in documents:
            doc_words = set(doc.lower().split())
            overlap = len(query_words & doc_words)
            scores.append(overlap / max(len(query_words), 1))
        return scores


class MockGenerationClient:
    def generate(self, system_prompt: str, user_content: str, *, max_tokens: int = 1024) -> GenerationResult:
        return GenerationResult(
            content=(
                "[MOCK GENERATION -- replace with AnthropicLLMClient/OpenAILLMClient]\n"
                f"Would respond to: {user_content[:120]}..."
            ),
            tokens=0,
            cost=0.0
        )

class LiteLLMClient:
    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model

    def generate(self, system_prompt: str, user_content: str, *, max_tokens: int = 1024) -> GenerationResult:
        response = completion(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            max_tokens=max_tokens
        )
        cost = completion_cost(completion_response=response) or 0.0
        return GenerationResult(
            content=response.choices[0].message.content or "",
            tokens=response.usage.total_tokens if response.usage else 0,
            cost=cost
        )

class LiteLLMClassifier:
    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model

    def classify(self, text: str, candidate_labels: list[str]) -> tuple[list[ClassificationResult], int, float]:
        labels_str = ", ".join(candidate_labels)
        prompt = (
            f"Classify the following text into exactly one of these labels: {labels_str}.\n"
            f"Respond with only the label name. If none fit perfectly, pick the closest one.\n\n"
            f"Text:\n{text}"
        )
        response = completion(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=10,
        )
        content = (response.choices[0].message.content or "").strip()
        cost = completion_cost(completion_response=response) or 0.0
        tokens = response.usage.total_tokens if response.usage else 0
        
        results = []
        for label in candidate_labels:
            if label.lower() == content.lower():
                results.append(ClassificationResult(label=label, score=0.9))
            else:
                results.append(ClassificationResult(label=label, score=0.1))
        
        return sorted(results, key=lambda r: r.score, reverse=True), tokens, cost

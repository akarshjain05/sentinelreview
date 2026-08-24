"""
Real HuggingFace zero-shot classifier.

Implements the existing ZeroShotClassifier protocol
(app/agents/model_clients.py) using transformers.pipeline(
"zero-shot-classification"), backed by a real NLI model
(facebook/bart-large-mnli by default) instead of MockZeroShotClassifier's
keyword matching.

IMPORTANT / HONEST STATUS: this was written and unit-tested against a fake
injected pipeline callable (see tests/test_hf_classifier.py), which proves
the wrapping/label-mapping/truncation logic is correct. It has NOT been run
against a real downloaded model -- this environment cannot reach
huggingface.co to pull model weights (see README's network constraints), so
there is no honest way to verify actual model inference from here. That
verification has to happen on a machine that can reach huggingface.co --
see the instructions after this file for exactly what to run.

Import of `transformers` is deferred into __init__ (not the module level)
so that code paths not using this classifier -- e.g. running the mocked
pipeline in CI, or in an environment without the ~500MB+ of torch/transformers
installed -- never pay that cost or need the dependency at all.
"""
from __future__ import annotations

from collections.abc import Callable

from app.agents.model_clients import ClassificationResult

# Signature of transformers' zero-shot-classification pipeline __call__:
# pipeline(text, candidate_labels=[...], multi_label=True) -> {"sequence": str, "labels": [...], "scores": [...]}
PipelineFn = Callable[..., dict]


class HFZeroShotClassifier:
    """
    Real transformer-based zero-shot classifier.

    Usage (on a machine that can reach huggingface.co):
        classifier = HFZeroShotClassifier()  # downloads facebook/bart-large-mnli on first use, ~1.6GB
        results = classifier.classify(
            "subprocess.call(x, shell=True)",
            ["sql_injection", "command_injection"],
        )

    For testing without the real model, inject a fake pipeline callable:
        classifier = HFZeroShotClassifier(pipeline_fn=lambda text, candidate_labels, multi_label:
            {"labels": candidate_labels, "scores": [0.9, 0.1]})
    """

    # Input length ceiling tied to the underlying model's context window
    # (BART: 1024 tokens). Truncate defensively (character count, not token
    # count -- a cheap conservative proxy) rather than letting the pipeline
    # raise on an unusually large code snippet or diff.
    MAX_INPUT_CHARS = 4000

    def __init__(
        self,
        model_name: str = "facebook/bart-large-mnli",
        device: int = -1,
        pipeline_fn: PipelineFn | None = None,
    ):
        self.model_name = model_name

        if pipeline_fn is not None:
            self._pipeline = pipeline_fn
            return

        try:
            from transformers import pipeline
        except ImportError as e:
            raise ImportError(
                "HFZeroShotClassifier requires the 'transformers' and 'torch' packages, "
                "which are not part of this project's default requirements.txt (they're "
                "large and only needed if you're actually running a real HF model). "
                "Install with: pip install transformers torch"
            ) from e

        self._pipeline = pipeline("zero-shot-classification", model=model_name, device=device)

    def classify(self, text: str, candidate_labels: list[str]) -> tuple[list[ClassificationResult], int, float]:
        if not text.strip() or not candidate_labels:
            return [], 0, 0.0

        truncated_text = text[: self.MAX_INPUT_CHARS]

        # NLI-based zero-shot models perform better against natural-language
        # labels ("sql injection") than snake_case tokens ("sql_injection"),
        # so translate for the call and map back to the original label the
        # rest of the pipeline (CWE_CANDIDATE_LABELS in app/agents/graph.py)
        # actually expects.
        natural_labels = [label.replace("_", " ") for label in candidate_labels]
        label_lookup = dict(zip(natural_labels, candidate_labels))

        result = self._pipeline(truncated_text, candidate_labels=natural_labels, multi_label=True)

        results = [
            ClassificationResult(label=label_lookup.get(nat_label, nat_label), score=float(score))
            for nat_label, score in zip(result["labels"], result["scores"])
        ]
        return results, 0, 0.0
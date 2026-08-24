import pytest
from app.agents.hf_classifier import HFZeroShotClassifier


def _fake_pipeline_factory(labels_in_order, scores_in_order):
    """
    Mimics the real transformers zero-shot-classification pipeline's return
    shape: {"sequence": ..., "labels": [...], "scores": [...]}, already
    sorted descending by score -- exactly what HFZeroShotClassifier.classify()
    has to consume correctly.
    """
    def fake_pipeline(text, candidate_labels, multi_label):
        return {"sequence": text, "labels": labels_in_order, "scores": scores_in_order}
    return fake_pipeline


def test_classify_maps_natural_language_labels_back_to_original_snake_case():
    # The pipeline receives natural-language labels ("sql injection") and
    # returns them; classify() must map them back to the caller's original
    # snake_case labels ("sql_injection") -- this round-trip is the actual
    # logic under test, not just pass-through.
    fake_pipeline = _fake_pipeline_factory(
        labels_in_order=["sql injection", "command injection"],
        scores_in_order=[0.87, 0.13],
    )
    classifier = HFZeroShotClassifier(pipeline_fn=fake_pipeline)

    results, _, _ = classifier.classify(
        "cursor.execute('SELECT * FROM x WHERE y=' + val)",
        ["sql_injection", "command_injection"],
    )

    assert results[0].label == "sql_injection"
    assert results[0].score == pytest.approx(0.87)
    assert results[1].label == "command_injection"
    assert results[1].score == pytest.approx(0.13)


def test_classify_preserves_pipeline_score_ordering():
    fake_pipeline = _fake_pipeline_factory(
        labels_in_order=["unsafe eval", "xss", "sql injection"],
        scores_in_order=[0.7, 0.2, 0.1],
    )
    classifier = HFZeroShotClassifier(pipeline_fn=fake_pipeline)

    results, _, _ = classifier.classify("eval(x)", ["sql_injection", "xss", "unsafe_eval"])

    assert [r.label for r in results] == ["unsafe_eval", "xss", "sql_injection"]


def test_classify_returns_empty_for_blank_text():
    classifier = HFZeroShotClassifier(pipeline_fn=_fake_pipeline_factory([], []))
    assert classifier.classify("   ", ["sql_injection"])[0] == []


def test_classify_returns_empty_for_no_candidate_labels():
    classifier = HFZeroShotClassifier(pipeline_fn=_fake_pipeline_factory([], []))
    assert classifier.classify("some code", [])[0] == []


def test_classify_truncates_oversized_input_before_calling_pipeline():
    received = {}

    def capturing_pipeline(text, candidate_labels, multi_label):
        received["text"] = text
        return {"sequence": text, "labels": candidate_labels, "scores": [1.0] * len(candidate_labels)}

    classifier = HFZeroShotClassifier(pipeline_fn=capturing_pipeline)
    huge_input = "x" * 10_000

    classifier.classify(huge_input, ["sql_injection"])

    assert len(received["text"]) == HFZeroShotClassifier.MAX_INPUT_CHARS


def test_missing_transformers_raises_clear_actionable_error(monkeypatch):
    """
    If transformers/torch aren't installed and no pipeline_fn is injected,
    the constructor should fail with a clear message telling the user what
    to pip install -- not a bare ModuleNotFoundError from deep inside
    transformers' import machinery.
    """
    import builtins
    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name == "transformers":
            raise ImportError("No module named 'transformers'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)

    with pytest.raises(ImportError, match="pip install transformers torch"):
        HFZeroShotClassifier()
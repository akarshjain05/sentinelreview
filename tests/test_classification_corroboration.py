from app.agents.graph import build_graph
from app.agents.state import ChangedFile, ReviewState
from app.sandbox.analyzers import MockStaticAnalyzer


class _AdversarialZeroShot:
    """
    A fake classifier that scores an IRRELEVANT label very high and the
    actually-correct label very low -- exactly the failure mode a
    general-purpose NLI model exhibited for real during evaluation (see
    README: a trivial cache class scored 84% confidence for "ssrf").

    If classification_node still takes the argmax across all labels, this
    test fails (severity gets driven to "high" by the irrelevant "ssrf"
    score). If it correctly looks up only the score for the finding's own
    matching label, this test passes (severity stays "medium", since the
    correct label's own score is low).
    """

    def classify(self, text, candidate_labels):
        from app.agents.model_clients import ClassificationResult

        results = []
        for label in candidate_labels:
            if label == "ssrf":
                results.append(ClassificationResult(label=label, score=0.95))  # irrelevant, high
            elif label == "sql_injection":
                results.append(ClassificationResult(label=label, score=0.05))  # correct, but low
            else:
                results.append(ClassificationResult(label=label, score=0.01))
        return sorted(results, key=lambda r: r.score, reverse=True), 0, 0.0


def test_classification_ignores_high_scoring_irrelevant_label():
    graph = build_graph(zero_shot=_AdversarialZeroShot(), static_analyzers={"mock": MockStaticAnalyzer()})

    state = ReviewState(
        repo_full_name="akarsh/x",
        pr_number=1,
        pr_title="Add query endpoint",
        pr_body="",
        head_sha="a",
        changed_files=[
            ChangedFile(
                path="app/db.py",
                diff="+ def q(conn, name):\n"
                     "+     cursor = conn.cursor()\n"
                     "+     cursor.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")\n",
            ),
        ],
    )

    result = graph.invoke(state)

    assert len(result["findings"]) >= 1
    finding = result["findings"][0]

    # The bug this test catches: severity should NOT be "high" just because
    # some unrelated label ("ssrf") scored 0.95. It should reflect the
    # matching label's own (low) score instead.
    assert finding.severity != "high"
    assert "ssrf" not in finding.explanation.lower()
    assert "sql_injection" in finding.explanation.lower() or finding.vulnerability_type == "CWE-89"


class _ConfidentCorrectZeroShot:
    """The inverse case: the classifier IS confident about the correct label. Severity should reflect that."""

    def classify(self, text, candidate_labels):
        from app.agents.model_clients import ClassificationResult

        return sorted(
            [ClassificationResult(label=label, score=0.9 if label == "command_injection" else 0.05)
             for label in candidate_labels],
            key=lambda r: r.score, reverse=True,
        ), 0, 0.0


def test_classification_raises_severity_when_matching_label_is_confident():
    graph = build_graph(zero_shot=_ConfidentCorrectZeroShot(), static_analyzers={"mock": MockStaticAnalyzer()})

    state = ReviewState(
        repo_full_name="akarsh/x", pr_number=1, pr_title="t", pr_body="", head_sha="a",
        changed_files=[
            ChangedFile(
                path="app/run.py",
                diff="+ import subprocess\n+ subprocess.call(cmd, shell=True)\n",
            ),
        ],
    )

    result = graph.invoke(state)
    assert len(result["findings"]) >= 1
    # Bandit produces two findings for this snippet: the generic "subprocess
    # module imported" advisory (no CWE) and the specific "shell=True"
    # command-injection finding (CWE-78) -- select the latter explicitly
    # rather than assuming ordering.
    finding = next(f for f in result["findings"] if f.cwe_id == "CWE-78")

    assert finding.severity == "high"
    assert "command_injection" in finding.explanation.lower()


def test_classification_handles_finding_with_no_cwe_mapping_gracefully():
    """
    Some Bandit findings have no CWE mapping at all (e.g. B404, the generic
    "subprocess module imported" advisory) -- CWE_TO_LABEL.get() correctly
    returns None for these, and classification_node must not crash or
    fabricate a corroboration claim for a label that was never actually
    checked against.
    """
    graph = build_graph(zero_shot=_ConfidentCorrectZeroShot(), static_analyzers={"mock": MockStaticAnalyzer()})

    state = ReviewState(
        repo_full_name="akarsh/x", pr_number=1, pr_title="t", pr_body="", head_sha="a",
        changed_files=[ChangedFile(path="app/run.py", diff="+ import subprocess\n")],
    )

    result = graph.invoke(state)  # must not raise
    for finding in result["findings"]:
        if finding.cwe_id is None:
            assert "No corresponding classifier label" in finding.explanation

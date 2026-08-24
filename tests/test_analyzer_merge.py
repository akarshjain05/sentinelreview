from app.agents.graph import merge_analyzer_findings
from app.sandbox.analyzers import RawFinding


def _rf(start_line, cwe_id, test_id="X", end_line=None):
    return RawFinding(
        start_line=start_line, end_line=end_line or start_line,
        test_id=test_id, cwe_id=cwe_id, severity="MEDIUM", confidence="MEDIUM",
        message="msg", code_snippet="code",
    )


def test_merges_findings_from_two_analyzers_agreeing_on_same_line_and_cwe():
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89", "B608")),
        ("semgrep", "app.py", _rf(10, "CWE-89", "sql-injection-string-concat")),
    ]
    merged = merge_analyzer_findings(findings)

    assert len(merged) == 1
    file_path, rf, analyzers = merged[0]  # noqa: RUF059
    assert set(analyzers) == {"bandit", "semgrep"}


def test_merges_findings_within_line_proximity_threshold():
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89")),
        ("semgrep", "app.py", _rf(12, "CWE-89")),  # 2 lines off -- still the same statement, e.g. multi-line call
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 1
    assert set(merged[0][2]) == {"bandit", "semgrep"}


def test_does_not_merge_findings_beyond_proximity_threshold():
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89")),
        ("semgrep", "app.py", _rf(50, "CWE-89")),  # same CWE, same file, but clearly a different instance
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 2


def test_does_not_merge_findings_with_different_cwe():
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89")),
        ("semgrep", "app.py", _rf(10, "CWE-78")),  # same line, different vulnerability class -- must stay separate
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 2


def test_does_not_merge_findings_in_different_files():
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89")),
        ("semgrep", "other.py", _rf(10, "CWE-89")),
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 2


def test_findings_with_no_cwe_are_never_merged_even_if_identical():
    """
    A finding with cwe_id=None (e.g. Bandit's generic "subprocess module
    imported" advisory) has no reliable identity to match on -- two such
    findings from different analyzers should never be silently collapsed
    into one, since we can't actually confirm they're the same issue.
    """
    findings = [
        ("bandit", "app.py", _rf(1, None, "B404")),
        ("semgrep", "app.py", _rf(1, None, "some-other-check")),
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 2


def test_single_analyzer_finding_passes_through_unmerged():
    findings = [("bandit", "app.py", _rf(10, "CWE-89"))]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 1
    assert merged[0][2] == ["bandit"]


def test_three_findings_same_cluster_all_merge_together():
    """Not just pairwise -- three nearby same-CWE findings from a mix of sources should all end up in one cluster."""
    findings = [
        ("bandit", "app.py", _rf(10, "CWE-89")),
        ("semgrep", "app.py", _rf(11, "CWE-89")),
        ("bandit", "app.py", _rf(12, "CWE-89")),  # e.g. bandit flagging both the query build and the execute call
    ]
    merged = merge_analyzer_findings(findings)
    assert len(merged) == 1
    assert len(merged[0][2]) == 3
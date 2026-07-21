"""
Real, permanent tests for BanditAnalyzer and SemgrepAnalyzer -- both the
single-file (analyze_file) and batch (analyze_files) APIs, against the
actual CLIs. These intentionally use real subprocesses (no mocking) and are
the slower half of the test suite by design: this is where detection
accuracy is actually verified. Fast pipeline-logic tests elsewhere inject
MockStaticAnalyzer instead of re-paying this cost for every test that has
nothing to do with whether Bandit/Semgrep themselves work correctly.

Semgrep tests are deliberately consolidated into as few real subprocess
calls as possible (batch calls covering multiple assertions each) rather
than one call per test case -- discovered while building this that
repeated Semgrep invocations degrade badly under CPU-constrained
conditions (single-core sandbox: individual warm calls run ~2-3s, but many
in a row pushed some past a 60s timeout). Fewer, larger real calls here
isn't just faster, it's also a more representative test of how the actual
pipeline uses these analyzers (one batched call per PR review), rather
than the less representative "one call per test method" shape.
"""
from app.sandbox.analyzers import BanditAnalyzer, SemgrepAnalyzer

_SQLI_CODE = 'cursor.execute("SELECT * FROM t WHERE n = " + name)\n'
_CMDI_CODE = "import subprocess\nsubprocess.call(cmd, shell=True)\n"
_SECRET_CODE = 'API_KEY = "sk_live_51H8f9aZ2xJmklsdf902"\n'
_SAFE_CODE = "def add(a, b):\n    return a + b\n"


class TestBanditAnalyzer:
    """Bandit's per-call overhead is small enough that per-test-method calls are fine (no consolidation needed)."""

    def test_analyze_file_detects_command_injection(self):
        findings = BanditAnalyzer().analyze_file("t.py", _CMDI_CODE)
        assert "CWE-78" in {f.cwe_id for f in findings}

    def test_analyze_file_no_findings_on_safe_code(self):
        assert BanditAnalyzer().analyze_file("t.py", _SAFE_CODE) == []

    def test_analyze_files_batch_attributes_findings_to_correct_file(self):
        results = BanditAnalyzer().analyze_files({
            "app/db.py": _SQLI_CODE, "app/exec.py": _CMDI_CODE, "app/safe.py": _SAFE_CODE,
        })
        assert any(f.cwe_id == "CWE-89" for f in results["app/db.py"])
        assert any(f.cwe_id == "CWE-78" for f in results["app/exec.py"])
        assert results["app/safe.py"] == []
        assert set(results.keys()) == {"app/db.py", "app/exec.py", "app/safe.py"}

    def test_analyze_files_batch_matches_individual_calls(self):
        """The batch API must never change *what* is detected, only how many subprocess calls it costs."""
        analyzer = BanditAnalyzer()
        files = {"app/db.py": _SQLI_CODE, "app/exec.py": _CMDI_CODE}
        batch = analyzer.analyze_files(files)
        individual = {path: analyzer.analyze_file(path, src) for path, src in files.items()}
        for path in files:
            assert sorted(f.cwe_id for f in batch[path] if f.cwe_id) == \
                   sorted(f.cwe_id for f in individual[path] if f.cwe_id)

    def test_analyze_files_empty_input_returns_empty(self):
        assert BanditAnalyzer().analyze_files({}) == {}


class TestSemgrepAnalyzer:
    """Consolidated into 2 real subprocess calls total for this class -- see module docstring."""

    def test_batch_detects_all_vulnerability_classes_with_correct_attribution(self):
        """
        One real Semgrep call covering everything that matters: correct
        detection across 3 vulnerability classes (including the hardcoded
        secret case Bandit misses -- the actual reason recall improved from
        0.900 to 1.000 on the real benchmark, see README), correct
        per-file attribution, zero false positives on safe code, and every
        input file present as a key even with no findings.
        """
        results = SemgrepAnalyzer().analyze_files({
            "app/db.py": _SQLI_CODE,
            "app/exec.py": _CMDI_CODE,
            "app/secret.py": _SECRET_CODE,
            "app/safe.py": _SAFE_CODE,
        })

        assert any(f.cwe_id == "CWE-89" for f in results["app/db.py"])
        assert any(f.cwe_id == "CWE-78" for f in results["app/exec.py"])
        assert any(f.cwe_id == "CWE-798" for f in results["app/secret.py"])
        assert results["app/safe.py"] == []
        assert set(results.keys()) == {"app/db.py", "app/exec.py", "app/secret.py", "app/safe.py"}

    def test_analyze_files_batch_matches_analyze_file(self):
        """The batch API must never change *what* is detected vs. calling analyze_file directly -- one extra real call to confirm."""
        analyzer = SemgrepAnalyzer()
        batch = analyzer.analyze_files({"app/db.py": _SQLI_CODE})
        individual = analyzer.analyze_file("app/db.py", _SQLI_CODE)
        assert sorted(f.cwe_id for f in batch["app/db.py"] if f.cwe_id) == \
               sorted(f.cwe_id for f in individual if f.cwe_id)

    def test_analyze_files_empty_input_returns_empty(self):
        """No subprocess call at all for empty input -- free, no consolidation needed."""
        assert SemgrepAnalyzer().analyze_files({}) == {}

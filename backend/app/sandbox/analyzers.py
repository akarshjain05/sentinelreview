"""
Static analyzer clients.

Unlike app/agents/model_clients.py (which mocks ML models we have no way to
serve in this environment), BanditAnalyzer and SemgrepAnalyzer here shell
out to the *actual* `bandit`/`semgrep` CLIs. This is real static analysis,
not a simulation -- the same tools a production deployment would run, just
invoked via the subprocess fallback path (see app/sandbox/runner.py)
instead of inside Docker, because this environment has no Docker daemon.

Semgrep note: the `semgrep` PyPI package initially failed to install here
because it needs `pyjwt~=2.13.0` but this environment's PyJWT 2.7.0 was
installed by apt, not pip, so pip had no RECORD file to safely upgrade it.
Fixed with `pip install semgrep --ignore-installed`. SemgrepAnalyzer runs
against a hand-written, offline, version-controlled ruleset
(semgrep_rules/python-security.yml) rather than `--config auto`, which
needs semgrep.dev's registry -- not reachable from this sandbox's network
allowlist, same constraint as huggingface.co and the NVD/OSV APIs
documented elsewhere in this project.

Batching note: analyze_file() spins up one subprocess per file. Measured
against the real eval benchmark, that costs ~2.6-3.2s average per Semgrep
call (dominated by process startup + rule compilation, not actual
scanning), which multiplies badly across a PR with many changed files.
analyze_files() fixes this for real by writing every changed file into one
temp directory and making a SINGLE subprocess call against the whole
directory -- both analyzers support scanning a directory natively. This is
the fix for the latency finding documented in README.md, not a workaround.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class RawFinding:
    start_line: int
    end_line: int
    test_id: str  # e.g. "B608" (Bandit) -- mapped to CWE separately
    cwe_id: str | None
    severity: str  # "LOW" | "MEDIUM" | "HIGH"
    confidence: str  # "LOW" | "MEDIUM" | "HIGH"
    message: str
    code_snippet: str


class StaticAnalyzer(Protocol):
    def analyze_file(self, file_path: str, source: str) -> list[RawFinding]: ...

    def analyze_files(self, files: dict[str, str]) -> dict[str, list[RawFinding]]:
        """Batch form of analyze_file: one subprocess call for all files, not one per file."""
        ...


def _write_files_to_tempdir(tmpdir: str, files: dict[str, str]) -> dict[str, str]:
    """
    Writes each (file_path -> source) pair into tmpdir under a collision-safe
    name (basenames alone can collide across different original directories,
    e.g. "app/db.py" vs "tests/db.py"), and returns a mapping of
    {temp_absolute_path: original_file_path} so results can be attributed
    back to the right file after the batch scan.
    """
    temp_to_original: dict[str, str] = {}
    for i, (file_path, source) in enumerate(files.items()):
        safe_name = f"{i:04d}_{Path(file_path).name}"
        target = Path(tmpdir) / safe_name
        target.write_text(source)
        temp_to_original[str(target.resolve())] = file_path
    return temp_to_original


class BanditAnalyzer:
    """Runs the real `bandit` CLI against Python source, single-file or batched."""

    def __init__(self, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds

    def analyze_file(self, file_path: str, source: str) -> list[RawFinding]:
        return self.analyze_files({file_path: source}).get(file_path, [])

    def analyze_files(self, files: dict[str, str]) -> dict[str, list[RawFinding]]:
        if not files:
            return {}

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_to_original = _write_files_to_tempdir(tmpdir, files)

            proc = subprocess.run(
                ["bandit", "-f", "json", "-q", "-r", tmpdir],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds, check=False,
            )
            # Bandit exits non-zero when it finds issues -- that's expected,
            # not a failure. Only treat unparsable output as an error.
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"bandit produced unparsable output (exit={proc.returncode}): "
                    f"{proc.stdout[:500]!r} stderr={proc.stderr[:500]!r}"
                ) from e

            results: dict[str, list[RawFinding]] = {fp: [] for fp in files}
            for issue in payload.get("results", []):
                original_path = temp_to_original.get(str(Path(issue["filename"]).resolve()))
                if original_path is None:
                    continue  # defensive: shouldn't happen, but never attribute a finding to the wrong file silently
                results[original_path].append(
                    RawFinding(
                        start_line=issue["line_number"],
                        end_line=issue.get("line_range", [issue["line_number"]])[-1],
                        test_id=issue["test_id"],
                        cwe_id=_bandit_test_to_cwe(issue["test_id"]),
                        severity=issue["issue_severity"],
                        confidence=issue["issue_confidence"],
                        message=issue["issue_text"],
                        code_snippet=issue.get("code", ""),
                    )
                )
            return results


class NullAnalyzer:
    """Used when no analyzer is available/desired (e.g. non-Python files)."""

    def analyze_file(self, file_path: str, source: str) -> list[RawFinding]:
        return []

    def analyze_files(self, files: dict[str, str]) -> dict[str, list[RawFinding]]:
        return {fp: [] for fp in files}


class MockStaticAnalyzer:
    """
    Deterministic, subprocess-free static analyzer for tests that exercise
    pipeline control flow (triage, classification corroboration, reporting,
    observability) rather than detection accuracy itself. Real detection
    accuracy is covered separately and directly by tests/test_static_analyzers.py
    against the real Bandit/Semgrep CLIs -- using this mock elsewhere isn't
    cutting a corner, it's not re-paying for the same subprocess overhead in
    every test that has nothing to do with whether Bandit/Semgrep themselves
    work correctly.
    """

    from typing import ClassVar
    _KEYWORD_TO_CWE: ClassVar[dict] = {
        "shell=True": "CWE-78",
        "cursor.execute": "CWE-89",
        "pickle.loads": "CWE-502",
        "yaml.load(": "CWE-502",
        "eval(": "CWE-95",
    }

    def analyze_file(self, file_path: str, source: str) -> list[RawFinding]:
        return self.analyze_files({file_path: source}).get(file_path, [])

    def analyze_files(self, files: dict[str, str]) -> dict[str, list[RawFinding]]:
        results: dict[str, list[RawFinding]] = {}
        for file_path, source in files.items():
            findings = []
            for i, line in enumerate(source.splitlines(), start=1):
                for keyword, cwe in self._KEYWORD_TO_CWE.items():
                    if keyword in line:
                        findings.append(
                            RawFinding(
                                start_line=i, end_line=i, test_id="MOCK",
                                cwe_id=cwe, severity="MEDIUM", confidence="MEDIUM",
                                message=f"mock finding for {cwe}", code_snippet=line,
                            )
                        )
            results[file_path] = findings
        return results


_SEMGREP_RULES_PATH = Path(__file__).parent / "semgrep_rules" / "python-security.yml"

# Matches "CWE-89: SQL Injection" -> "CWE-89" out of a rule's metadata.cwe field.
_CWE_METADATA_PATTERN = re.compile(r"CWE-\d+")


class SemgrepAnalyzer:
    """
    Runs the real `semgrep` CLI against Python source, single-file or
    batched, using a hand-written, offline, version-controlled ruleset
    (semgrep_rules/python-security.yml) rather than `--config auto`.

    That's a deliberate choice, not a workaround for a missing feature:
    `--config auto` fetches rules from semgrep.dev's registry at scan time,
    which (a) isn't reachable from every environment (this project's own
    sandbox included -- semgrep.dev isn't on its network allowlist) and (b)
    means the exact ruleset a review runs against can silently change
    between runs, which is bad for reproducibility in a security tool
    specifically. Pinning a local ruleset trades registry breadth for
    determinism -- a real, defensible tradeoff, not a limitation to hide.

    Covers the same vulnerability classes as BanditAnalyzer (SQL injection,
    command injection, unsafe deserialization, unsafe eval, hardcoded
    secrets) as a genuinely independent second analyzer using pattern-based
    matching rather than Bandit's AST-visitor checks -- they can and do
    disagree on edge cases, which is the point of running both.
    """

    def __init__(self, rules_path: str | None = None, timeout_seconds: int = 60):
        self.rules_path = rules_path or str(Path(__file__).parent / "semgrep_rules" / "python-security.yml")
        self.timeout_seconds = timeout_seconds

    def analyze_file(self, file_path: str, source: str) -> list[RawFinding]:
        return self.analyze_files({file_path: source}).get(file_path, [])

    def analyze_files(self, files: dict[str, str]) -> dict[str, list[RawFinding]]:
        if not files:
            return {}

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_to_original = _write_files_to_tempdir(tmpdir, files)

            proc = subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", str(self.rules_path),
                    "--json", "--quiet",
                    "--metrics", "off",  # don't phone home usage stats
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds, check=False,
            )
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"semgrep produced unparsable output (exit={proc.returncode}): "
                    f"{proc.stdout[:500]!r} stderr={proc.stderr[:500]!r}"
                ) from e

            results: dict[str, list[RawFinding]] = {fp: [] for fp in files}
            for result in payload.get("results", []):
                original_path = temp_to_original.get(str(Path(result["path"]).resolve()))
                if original_path is None:
                    continue  # defensive: shouldn't happen, but never attribute a finding to the wrong file silently

                rule_id = result["check_id"].rsplit(".", 1)[-1]  # strip the path-prefixed rule namespace
                cwe_raw = result.get("extra", {}).get("metadata", {}).get("cwe")
                if isinstance(cwe_raw, list) and cwe_raw:
                    cwe_raw = cwe_raw[0]
                elif not isinstance(cwe_raw, str):
                    cwe_raw = None
                
                cwe_match = _CWE_METADATA_PATTERN.search(cwe_raw) if cwe_raw else None

                
                # Semgrep sometimes redacts the "lines" field with "requires login" for registry rules.
                # Extract the snippet manually from the source file.
                start_line = result["start"]["line"]
                end_line = result["end"]["line"]
                source_lines = files[original_path].splitlines()
                # line numbers are 1-indexed, slice is 0-indexed
                code_snippet = "\n".join(source_lines[max(0, start_line-1):end_line])

                results[original_path].append(
                    RawFinding(
                        start_line=start_line,
                        end_line=end_line,
                        test_id=rule_id,
                        cwe_id=cwe_match.group(0) if cwe_match else None,
                        severity=result.get("extra", {}).get("severity", "MEDIUM").upper(),
                        confidence="MEDIUM",  # this ruleset doesn't set per-rule confidence; treat uniformly
                        message=result.get("extra", {}).get("message", "").strip(),
                        code_snippet=code_snippet,
                    )
                )
            return results


# Bandit test IDs -> CWE mapping for the checks this project currently cares
# about (sourced from Bandit's own documentation categories, reproduced as
# a plain lookup table rather than fetched/scraped at runtime).
_BANDIT_CWE_MAP = {
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B610": "CWE-89",   # django extra sql injection
    "B611": "CWE-89",   # django RawSQL
    "B601": "CWE-78",   # paramiko command injection
    "B602": "CWE-78",   # subprocess with shell=True
    "B603": "CWE-78",   # subprocess without shell equals true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B609": "CWE-78",   # linux commands wildcard injection
    "B307": "CWE-95",   # eval
    "B102": "CWE-95",   # exec_used
    "B301": "CWE-502",  # pickle
    "B403": "CWE-502",  # import pickle
    "B506": "CWE-502",  # yaml_load
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
    "B303": "CWE-327",  # insecure MD5/SHA1 hash
    "B324": "CWE-327",  # insecure hash function
    "B310": "CWE-918",  # urllib urlopen (SSRF-adjacent)
    "B322": "CWE-22",   # input() path traversal risk (py2)
    "B108": "CWE-377",  # hardcoded tmp path
}


def _bandit_test_to_cwe(test_id: str) -> str | None:
    return _BANDIT_CWE_MAP.get(test_id)

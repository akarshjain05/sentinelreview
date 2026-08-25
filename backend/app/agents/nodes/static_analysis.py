from app.agents.state import PipelineFinding, ReviewState
from app.security.guardrails import assert_tool_allowed
from app.services.static_analysis import merge_analyzer_findings


def make_static_analysis_node(static_analyzers: dict):
    def static_analysis_node(state: ReviewState) -> dict:
        assert_tool_allowed("static_analysis", "run_semgrep")
        assert_tool_allowed("static_analysis", "run_bandit")
        files_to_scan = {cf.path: cf.diff for cf in state.changed_files if cf.path in state.files_to_review}
        raw_by_analyzer = []
        if files_to_scan:
            for analyzer_name, analyzer in static_analyzers.items():
                try:
                    results_by_file = analyzer.analyze_files(files_to_scan)
                except Exception as e:
                    raise RuntimeError(f"Static analyzer '{analyzer_name}' failed to run: {e}") from e
                for file_path, raw_findings in results_by_file.items():
                    for rf in raw_findings:
                        raw_by_analyzer.append((analyzer_name, file_path, rf))

        merged = merge_analyzer_findings(raw_by_analyzer)

        findings: list[PipelineFinding] = []
        for file_path, rf, analyzer_names in merged:
            raw_sev = (rf.severity or "medium").lower()
            if raw_sev == "error":
                mapped_sev = "high"
            elif raw_sev == "warning":
                mapped_sev = "medium"
            else:
                mapped_sev = raw_sev if raw_sev in ("critical", "high", "medium", "low", "info") else "medium"

            if isinstance(rf.confidence, str):
                c = rf.confidence.lower()
                mapped_conf = 0.8 if c == "high" else (0.2 if c == "low" else 0.5)
            else:
                mapped_conf = float(rf.confidence)

            findings.append(
                PipelineFinding(
                    file_path=file_path,
                    start_line=rf.start_line,
                    end_line=rf.end_line,
                    cwe_id=rf.cwe_id,
                    vulnerability_type=rf.test_id,
                    severity=mapped_sev,
                    confidence=mapped_conf,
                    source="+".join(analyzer_names),
                    explanation=rf.message,
                    code_snippet=rf.code_snippet,
                )
            )

        return {"findings": findings}
    return static_analysis_node

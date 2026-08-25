from app.agents.state import ReviewState, VerificationOutcome
from app.security.guardrails import assert_tool_allowed

def make_verification_node(static_analyzers: dict):
    def verification_node(state: ReviewState) -> dict:
        assert_tool_allowed("verification", "apply_patch_sandboxed")

        outcomes: list[VerificationOutcome] = []
        for idx, patch in enumerate(state.patch_suggestions):
            finding = state.findings[patch.finding_index]
            
            patched_code = patch.diff
            issue_resolved = True
            introduced_new_findings = False
            log_output = ""
            
            for analyzer_name, analyzer in static_analyzers.items():
                try:
                    results = analyzer.analyze_file(finding.file_path, patched_code)
                    if results:
                        same_finding = any(rf.cwe_id == finding.cwe_id for rf in results)
                        if same_finding:
                            issue_resolved = False
                            log_output += f"{analyzer_name} still found {finding.cwe_id} in patched code.\n"
                        else:
                            introduced_new_findings = True
                            log_output += f"{analyzer_name} found new issues in patched code.\n"
                except Exception as e:
                    issue_resolved = False
                    log_output += f"Analyzer {analyzer_name} failed: {e}\n"
            
            outcomes.append(
                VerificationOutcome(
                    patch_index=idx,
                    issue_resolved=issue_resolved,
                    tests_passed=False,
                    build_succeeded=False,
                    introduced_new_findings=introduced_new_findings,
                    log=log_output or "Static verification passed. Dynamic sandboxed verification not yet implemented.",
                )
            )
        return {"verification_outcomes": outcomes}
    return verification_node

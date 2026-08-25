from app.sandbox.analyzers import RawFinding


def merge_analyzer_findings(
    raw_findings: list[tuple[str, str, RawFinding]]
) -> list[tuple[str, RawFinding, list[str]]]:
    """
    Merges duplicate findings across multiple analyzers.
    Returns: list of (file_path, merged_finding, list_of_analyzer_names)
    """
    clusters: list[tuple[str, RawFinding, list[str]]] = []
    
    for analyzer_name, file_path, rf in raw_findings:
        if rf.cwe_id is None:
            # Cannot merge if no reliable identity
            clusters.append((file_path, rf, [analyzer_name]))
            continue
            
        matched_cluster = None
        for i, (c_file, c_rf, c_names) in enumerate(clusters):
            if c_file == file_path and c_rf.cwe_id == rf.cwe_id and abs(rf.start_line - c_rf.start_line) <= 3:
                matched_cluster = i
                break
                    
        if matched_cluster is not None:
            c_file, c_rf, c_names = clusters[matched_cluster]
            c_names.append(analyzer_name)
            c_rf.start_line = min(c_rf.start_line, rf.start_line)
            c_rf.end_line = max(c_rf.end_line, rf.end_line)
        else:
            clusters.append((file_path, rf, [analyzer_name]))
            
    return clusters

def get_default_analyzers():
    from app.sandbox.analyzers import SemgrepAnalyzer
    # Default fallback if none injected
    return {"semgrep": SemgrepAnalyzer()}

from app.agents.state import ReviewState, SecurityFlag
from app.core.config import get_settings
from app.agents.tools import sanitize_untrusted_text, assert_tool_allowed

def triage_node(state: ReviewState) -> dict:
    assert_tool_allowed("triage", "list_changed_files")
    sanitized_title = sanitize_untrusted_text(state.pr_title, source="pr_title")
    sanitized_body = sanitize_untrusted_text(state.pr_body, source="pr_body")
    new_flags = list(state.security_flags)
    for result in (sanitized_title, sanitized_body):
        if result.flagged:
            new_flags.append(SecurityFlag(source="pr_metadata", matched_patterns=result.matched_patterns))

    files_to_review, skipped = [], []
    for f in state.changed_files:
        if f.is_doc_file:
            skipped.append(f.path)
            continue
        files_to_review.append(f.path)

    settings = get_settings()
    if len(files_to_review) > settings.max_files_per_review:
        skipped.extend(files_to_review[settings.max_files_per_review:])
        files_to_review = files_to_review[:settings.max_files_per_review]

    return {"files_to_review": files_to_review, "skipped_files": skipped, "security_flags": new_flags}

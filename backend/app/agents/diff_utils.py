"""
Extracts real, syntactically-valid source code from unified-diff text so it
can be handed to a static analyzer (which needs parseable code, not diff
markup with +/-/@@ prefixes).

Handles both a full unified diff (with @@ hunk headers and --- / +++ file
lines) and the simplified "every changed line prefixed with +" format used
in this project's own test fixtures and GitHub's compare API `patch` field.
"""
import re

_HUNK_HEADER = re.compile(r"^@@ .* @@")


def extract_added_lines(diff_text: str) -> str:
    """
    Returns only the added ('+') lines from a diff, with the diff marker
    stripped, in original order. This is what a PR reviewer actually wants
    to run a static analyzer against: the code as it will exist after the
    PR merges, not a mix of old and new code, and not diff punctuation that
    would break a parser.

    Note: this only reconstructs the *changed* lines, not full file context
    (a line like `cursor.execute(x)` split across a diff hunk without its
    surrounding function may occasionally cause an analyzer to lose context
    it would have had against the full file). Production version should
    fetch full post-PR file content via the GitHub Contents API rather than
    relying on the diff alone -- tracked as a follow-up, this stopgap is
    sufficient for line-level pattern-based checks like Bandit's.
    """
    lines_out = []
    for line in diff_text.splitlines():
        if not line:
            continue
        if _HUNK_HEADER.match(line) or line.startswith(("---", "+++", "diff --git", "index ")):
            continue
        if line.startswith("+"):
            lines_out.append(line[1:] if not line.startswith("+ ") else line[2:])
        elif line.startswith("-"):
            continue  # removed line, not part of the resulting file
        elif line.startswith(" "):
            lines_out.append(line[1:])  # unchanged context line
        else:
            # Not diff-prefixed at all (e.g. tests passing raw source) --
            # pass through unchanged rather than dropping content.
            lines_out.append(line)
    return "\n".join(lines_out) + "\n"

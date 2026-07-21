from app.agents.diff_utils import extract_added_lines


def test_extracts_added_lines_simple_plus_prefix():
    diff = "+ def foo():\n+     return 1\n"
    result = extract_added_lines(diff)
    assert result == "def foo():\n    return 1\n"


def test_drops_removed_lines():
    diff = "+ def foo():\n-     return 0\n+     return 1\n"
    result = extract_added_lines(diff)
    assert "return 0" not in result
    assert "return 1" in result


def test_keeps_context_lines():
    diff = " def foo():\n+     return 1\n"
    result = extract_added_lines(diff)
    assert "def foo():" in result
    assert "return 1" in result


def test_strips_hunk_headers_and_file_markers():
    diff = (
        "diff --git a/x.py b/x.py\n"
        "index abc123..def456 100644\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,2 @@\n"
        "+import os\n"
        "+os.system('ls')\n"
    )
    result = extract_added_lines(diff)
    assert "diff --git" not in result
    assert "@@" not in result
    assert "import os" in result
    assert "os.system" in result


def test_result_is_valid_python_syntax():
    diff = "+ import subprocess\n+ subprocess.call(x, shell=True)\n"
    result = extract_added_lines(diff)
    compile(result, "<test>", "exec")  # raises SyntaxError if invalid -- this is the real regression check

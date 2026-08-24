import httpx
import pytest
import respx
from app.services.github_client import (
    GitHubAPIError,
    fetch_pr_files,
    is_doc_file,
    is_test_file,
)

_PAGE_1 = [
    {"filename": "app/search.py", "status": "modified", "patch": "@@ -1,2 +1,3 @@\n+cursor.execute(x)"},
]
_PAGE_2 = [
    {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1 @@\n+docs update"},
]
_NEXT_URL = "https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files?per_page=100&page=2"


@respx.mock
def test_fetch_pr_files_parses_real_response_shape():
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )

    files = fetch_pr_files("akarsh", "sentinelreview", 42, "ghs_faketoken")

    assert len(files) == 1
    assert files[0].filename == "app/search.py"
    assert files[0].status == "modified"
    assert "cursor.execute" in files[0].patch


@respx.mock
def test_fetch_pr_files_follows_link_header_across_pages():
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=_PAGE_2)
        return httpx.Response(200, json=_PAGE_1, headers={"Link": f'<{_NEXT_URL}>; rel="next"'})

    route = respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        side_effect=responder
    )

    files = fetch_pr_files("akarsh", "sentinelreview", 42, "ghs_faketoken")

    assert {f.filename for f in files} == {"app/search.py", "README.md"}
    assert route.call_count == 2


@respx.mock
def test_fetch_pr_files_does_not_re_request_when_no_next_link():
    """
    Same regression class as app/knowledge/ghsa_ingest.py's earlier bug:
    Link-header-driven pagination must make exactly one request when
    there's no next page, not loop max_pages times regardless.
    """
    route = respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )

    files = fetch_pr_files("akarsh", "sentinelreview", 42, "ghs_faketoken", max_pages=10)

    assert len(files) == 1
    assert route.call_count == 1


@respx.mock
def test_fetch_pr_files_handles_binary_file_with_no_patch():
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(200, json=[
            {"filename": "assets/logo.png", "status": "added"},  # no "patch" key -- binary file
        ])
    )

    files = fetch_pr_files("akarsh", "sentinelreview", 42, "ghs_faketoken")
    assert files[0].patch is None


@respx.mock
def test_fetch_pr_files_raises_on_error_response():
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )

    with pytest.raises(GitHubAPIError, match="404"):
        fetch_pr_files("akarsh", "sentinelreview", 42, "ghs_faketoken")


def test_is_doc_file():
    assert is_doc_file("README.md") is True
    assert is_doc_file("docs/guide.rst") is True
    assert is_doc_file("app/main.py") is False


def test_is_test_file():
    assert is_test_file("tests/test_foo.py") is True
    assert is_test_file("app/test_bar.py") is True
    assert is_test_file("app/main.py") is False
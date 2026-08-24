import httpx
import pytest
import respx
from app.knowledge.ghsa_ingest import (
    GHSAIngestError,
    advisories_to_knowledge_documents,
    fetch_advisories,
)

_PAGE_1 = [
    {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "SQL Injection in example-orm",
        "description": "A crafted query parameter could bypass parameterization in example-orm < 2.1.4.",
        "severity": "high",
        "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
    },
]
_PAGE_2 = [
    {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Deserialization vulnerability in example-cache",
        "description": "example-cache deserializes cache entries with pickle without validation.",
        "severity": "critical",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "cwes": [{"cwe_id": "CWE-502", "name": "Deserialization"}],
    },
]
_NEXT_PAGE_URL = "https://api.github.com/advisories?per_page=25&page=2"


@respx.mock
def test_fetch_advisories_parses_real_response_shape():
    respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )
    advisories = fetch_advisories(ecosystem="pip", per_page=25, max_pages=4)
    assert len(advisories) == 1
    assert advisories[0].ghsa_id == "GHSA-xxxx-yyyy-zzzz"
    assert advisories[0].cwe_ids == ["CWE-89"]


@respx.mock
def test_fetch_advisories_follows_link_header_across_pages():
    def responder(request: httpx.Request) -> httpx.Response:
        # NOTE: naive substring checks like `"page=2" in str(url)` are a trap
        # here -- "per_page=25" contains "page=2" as a literal substring.
        # Parse the actual query param instead.
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=_PAGE_2)  # last page, no Link header
        return httpx.Response(
            200, json=_PAGE_1, headers={"Link": f'<{_NEXT_PAGE_URL}>; rel="next"'}
        )

    route = respx.get("https://api.github.com/advisories").mock(side_effect=responder)

    advisories = fetch_advisories(max_pages=4)

    assert len(advisories) == 2
    assert {a.ghsa_id for a in advisories} == {"GHSA-xxxx-yyyy-zzzz", "GHSA-aaaa-bbbb-cccc"}
    assert route.call_count == 2  # exactly two real HTTP calls: page 1, then the linked page 2


@respx.mock
def test_fetch_advisories_does_not_re_request_when_no_next_link():
    """
    Regression test for the real bug found against production data:
    manually building page=1,2,3 made 3 HTTP requests regardless of whether
    the endpoint paginated that way -- against the real GitHub advisories
    endpoint this returned the same first page 3 times (confirmed: a
    --pages 3 run against 2 ecosystems produced exactly 150 rows that
    deduplicated to 50, a clean 3x). Following the Link header means with
    no "next" link present, exactly ONE request is made even if max_pages=4.
    """
    route = respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )
    advisories = fetch_advisories(max_pages=4)
    assert len(advisories) == 1
    assert route.call_count == 1


@respx.mock
def test_fetch_advisories_retries_once_on_rate_limit_then_succeeds():
    route = respx.get("https://api.github.com/advisories")
    route.side_effect = [
        httpx.Response(403, headers={"Retry-After": "0"}, json={"message": "rate limit exceeded"}),
        httpx.Response(200, json=_PAGE_1),
    ]
    advisories = fetch_advisories(max_pages=4, max_retries_on_rate_limit=1)
    assert len(advisories) == 1


@respx.mock
def test_fetch_advisories_raises_after_exhausting_retries():
    respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(403, headers={"Retry-After": "0"}, json={"message": "rate limit exceeded"})
    )
    with pytest.raises(GHSAIngestError):
        fetch_advisories(max_pages=1, max_retries_on_rate_limit=1)


@respx.mock
def test_advisories_to_knowledge_documents_shape():
    respx.get("https://api.github.com/advisories").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )
    advisories = fetch_advisories(max_pages=4)
    docs = advisories_to_knowledge_documents(advisories)
    assert docs[0]["source"] == "ghsa"
    assert docs[0]["external_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert docs[0]["cwe_ids"] == "CWE-89"
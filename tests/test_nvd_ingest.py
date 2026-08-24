import httpx
import respx
from app.knowledge.nvd_ingest import (
    advisories_to_knowledge_documents,
    fetch_advisories,
)

_PAGE_1 = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-1234",
                "descriptions": [
                    {"lang": "en", "value": "A terrible SQL injection."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "CRITICAL"}}
                    ]
                },
                "weaknesses": [
                    {
                        "description": [{"lang": "en", "value": "CWE-89"}]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2023-5678",
                "descriptions": [
                    {"lang": "en", "value": "XSS in the search bar."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "MEDIUM"}}
                    ]
                },
                "weaknesses": [
                    {
                        "description": [{"lang": "en", "value": "CWE-79"}]
                    }
                ]
            }
        }
    ]
}

_PAGE_2 = {
    "resultsPerPage": 2,
    "startIndex": 2,
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-9999",
                "descriptions": [
                    {"lang": "en", "value": "Remote code execution."}
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {"baseSeverity": "HIGH"}
                    ]
                },
                "weaknesses": []
            }
        }
    ]
}

@respx.mock
def test_nvd_fetch_advisories_parses_real_response_shape():
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )
    advisories = fetch_advisories(per_page=2, max_pages=1)
    assert len(advisories) == 2
    assert advisories[0].nvd_id == "CVE-2023-1234"
    assert advisories[0].cwe_ids == ["CWE-89"]
    assert advisories[0].severity == "critical"

@respx.mock
def test_nvd_fetch_advisories_paginates_until_total_results():
    def responder(request: httpx.Request) -> httpx.Response:
        start_index = int(request.url.params.get("startIndex", "0"))
        if start_index == 0:
            return httpx.Response(200, json=_PAGE_1)
        return httpx.Response(200, json=_PAGE_2)

    route = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(side_effect=responder)

    advisories = fetch_advisories(per_page=2, max_pages=4)

    assert len(advisories) == 3
    assert {a.nvd_id for a in advisories} == {"CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9999"}
    assert route.call_count == 2

@respx.mock
def test_nvd_fetch_advisories_retries_on_rate_limit():
    route = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json=_PAGE_1),
    ]
    advisories = fetch_advisories(max_pages=1)
    assert len(advisories) == 2
    assert route.call_count == 2

@respx.mock
def test_nvd_advisories_to_knowledge_documents_shape():
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(200, json=_PAGE_1)
    )
    advisories = fetch_advisories(max_pages=1)
    docs = advisories_to_knowledge_documents(advisories)
    assert docs[0]["source"] == "nvd"
    assert docs[0]["external_id"] == "CVE-2023-1234"
    assert docs[0]["cwe_ids"] == "CWE-89"

"""
Ingests NVD CVEs into the KnowledgeDocument table.

This hits the real NVD CVE API endpoint (`GET https://services.nvd.nist.gov/rest/json/cves/2.0`),
handles pagination via `startIndex` and `resultsPerPage`, and respects rate-limit backoff.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class IngestedAdvisory:
    nvd_id: str
    summary: str
    description: str
    cwe_ids: list[str]
    severity: str
    url: str


class NVDIngestError(RuntimeError):
    pass


def fetch_advisories(
    *,
    ecosystem: str | None = None,  # NVD doesn't explicitly filter by OSV-style ecosystems natively on this endpoint, but we accept it for API parity
    per_page: int = 100,
    max_pages: int = 4,
    api_key: str | None = None,
    client: httpx.Client | None = None,
    max_retries_on_rate_limit: int = 3,
) -> list[IngestedAdvisory]:
    """
    Fetch advisories from the real NVD API.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=30.0)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    advisories: list[IngestedAdvisory] = []
    
    start_index = 0

    try:
        for _page_number in range(max_pages):
            retries = 0
            while True:
                params = {
                    "startIndex": start_index,
                    "resultsPerPage": per_page,
                }
                
                # If ecosystem is provided as keyword, NVD supports keywordSearch
                if ecosystem:
                    params["keywordSearch"] = ecosystem  # type: ignore
                    
                response = client.get(NVD_API_BASE, params=params, headers=headers)
                if response.status_code == 200:
                    break
                if response.status_code in (403, 429) and retries < max_retries_on_rate_limit:
                    # NVD may or may not return Retry-After, fallback to 2^retries
                    wait = int(response.headers.get("Retry-After", str(2 ** retries)))
                    time.sleep(wait)
                    retries += 1
                    continue
                raise NVDIngestError(
                    f"NVD request failed ({response.status_code}): {response.text[:300]}"
                )

            page_data = response.json()
            cves = page_data.get("vulnerabilities", [])
            if not cves:
                break

            for item in cves:
                cve_data = item.get("cve", {})
                nvd_id = cve_data.get("id", "")
                
                descriptions = cve_data.get("descriptions", [])
                en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                
                cwes = []
                weaknesses = cve_data.get("weaknesses", [])
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                            cwes.append(desc["value"])
                            
                metrics = cve_data.get("metrics", {})
                severity = "unknown"
                for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metrics.get(cvss_version):
                        metric = metrics[cvss_version][0]
                        cvss_data = metric.get("cvssData", {})
                        if "baseSeverity" in cvss_data:
                            severity = cvss_data["baseSeverity"].lower()
                            break
                        elif "baseSeverity" in metric:
                            severity = metric["baseSeverity"].lower()
                            break

                advisories.append(
                    IngestedAdvisory(
                        nvd_id=nvd_id,
                        summary=nvd_id,
                        description=en_desc,
                        cwe_ids=cwes,
                        severity=severity,
                        url=f"https://nvd.nist.gov/vuln/detail/{nvd_id}",
                    )
                )

            total_results = page_data.get("totalResults", 0)
            start_index += len(cves)
            
            if start_index >= total_results:
                break
                
        return advisories
    finally:
        if owns_client:
            client.close()


def advisories_to_knowledge_documents(advisories: list[IngestedAdvisory]) -> list[dict]:
    """Shape ingested advisories into rows ready for KnowledgeDocument insertion."""
    docs = []
    for adv in advisories:
        docs.append({
            "source": "nvd",
            "external_id": adv.nvd_id,
            "title": adv.summary or adv.nvd_id,
            "content": adv.description,
            "cwe_ids": ",".join(adv.cwe_ids) if adv.cwe_ids else None,
            "url": adv.url,
        })
    return docs

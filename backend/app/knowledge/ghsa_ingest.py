"""
Ingests GitHub Security Advisories (GHSA) into the KnowledgeDocument table.

This hits the real GitHub REST API endpoint (`GET /advisories`), handles
pagination and rate-limit backoff correctly, and is unit-tested against a
mocked HTTP response (see tests/test_ghsa_ingest.py).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

GITHUB_API_BASE = "https://api.github.com"


@dataclass
class IngestedAdvisory:
    ghsa_id: str
    summary: str
    description: str
    cwe_ids: list[str]
    severity: str
    url: str


class GHSAIngestError(RuntimeError):
    pass


def fetch_advisories(
    *,
    ecosystem: str | None = None,
    per_page: int = 25,
    max_pages: int = 4,
    github_token: str | None = None,
    client: httpx.Client | None = None,
    max_retries_on_rate_limit: int = 1,
) -> list[IngestedAdvisory]:
    """
    Fetch advisories from the real GitHub Advisory Database API.

    Paginates by following the response's `Link` header (rel="next"), per
    GitHub's own documented pagination method
    (https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)
    -- NOT by manually incrementing a `page=` query parameter.

    That distinction matters: an earlier version of this function built
    `page=1`, `page=2`, `page=3` itself, which silently returned the *same*
    first page three times in a row against real production data (verified:
    a `--ecosystems pip npm --pages 3` run produced exactly 75 fetched items
    per ecosystem that deduplicated down to 25 unique advisories each --
    a clean 3x, consistent with every page request being ignored and
    re-serving page 1). Following the Link header is correct regardless of
    whether a given GitHub endpoint implements offset or cursor pagination
    under the hood.

    Respects `Retry-After` on 403/429 rate-limit responses, up to
    `max_retries_on_rate_limit` times, then raises rather than looping
    forever -- a webhook handler or ingestion cron job should never hang
    indefinitely on a shared/unauthenticated rate limit.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    advisories: list[IngestedAdvisory] = []
    next_url: str | None = f"{GITHUB_API_BASE}/advisories"
    next_params: dict | None = {"per_page": per_page}
    if ecosystem:
        next_params["ecosystem"] = ecosystem  # type: ignore

    try:
        for _page_number in range(1, max_pages + 1):
            if next_url is None:
                break

            retries = 0
            while True:
                response = client.get(next_url, params=next_params, headers=headers)
                if response.status_code == 200:
                    break
                if response.status_code in (403, 429) and retries < max_retries_on_rate_limit:
                    wait = int(response.headers.get("Retry-After", "2"))
                    time.sleep(wait)
                    retries += 1
                    continue
                raise GHSAIngestError(
                    f"GitHub advisories request failed ({response.status_code}): {response.text[:300]}"
                )

            page_data = response.json()
            if not page_data:
                break

            for item in page_data:
                advisories.append(
                    IngestedAdvisory(
                        ghsa_id=item["ghsa_id"],
                        summary=item.get("summary", ""),
                        description=item.get("description", "") or item.get("summary", ""),
                        cwe_ids=[c["cwe_id"] for c in item.get("cwes", []) if "cwe_id" in c],
                        severity=item.get("severity", "unknown"),
                        url=item.get("html_url", ""),
                    )
                )

            # This is the actual fix: advance using the Link header's
            # rel="next" URL (httpx parses this into response.links), not by
            # guessing the next page= value ourselves. If there's no "next"
            # link, we've genuinely reached the end of the result set.
            next_link = response.links.get("next")
            if next_link is None:
                next_url = None
            else:
                next_url = next_link["url"]
                next_params = None  # the next URL already has all query params baked in
        return advisories
    finally:
        if owns_client:
            client.close()


def advisories_to_knowledge_documents(advisories: list[IngestedAdvisory]) -> list[dict]:
    """Shape ingested advisories into rows ready for KnowledgeDocument insertion."""
    docs = []
    for adv in advisories:
        docs.append({
            "source": "ghsa",
            "external_id": adv.ghsa_id,
            "title": adv.summary or adv.ghsa_id,
            "content": adv.description,
            "cwe_ids": ",".join(adv.cwe_ids) if adv.cwe_ids else None,
            "url": adv.url,
        })
    return docs
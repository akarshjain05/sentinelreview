"""
Fetches a pull request's changed files from the real GitHub REST API, using
an installation token obtained via app.auth.github_app.get_installation_token.

This is the piece that turns "we can authenticate as the GitHub App" into
"we can actually review something" -- without it, the auth chain built
earlier has nothing to fetch and the pipeline has nothing to scan.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

GITHUB_API_BASE = "https://api.github.com"


@dataclass
class PRFile:
    filename: str
    status: str  # "added" | "modified" | "removed" | "renamed"
    patch: str | None  # unified diff text; None for binary or very large files


class GitHubAPIError(RuntimeError):
    pass


def fetch_pr_files(
    owner: str,
    repo: str,
    pull_number: int,
    installation_token: str,
    *,
    per_page: int = 100,
    max_pages: int = 10,
    client: httpx.Client | None = None,
) -> list[PRFile]:
    """
    Fetches every changed file in a PR, following the response's Link
    header for pagination -- the same correct pattern used in
    app/knowledge/ghsa_ingest.py, after that module's earlier bug (manually
    guessing page= numbers, which silently re-fetched the same page 3x
    against the real GitHub advisories endpoint) showed why guessing at
    pagination is unsafe against this API.

    max_pages * per_page = 1000 files by default, comfortably above
    GitHub's own 3000-file-per-PR API limit for realistic PRs, while still
    bounding worst-case work for a pathological one.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0)
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    files: list[PRFile] = []
    next_url: str | None = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pull_number}/files"
    next_params: dict | None = {"per_page": per_page}

    try:
        for _ in range(max_pages):
            if next_url is None:
                break

            response = client.get(next_url, params=next_params, headers=headers)
            if response.status_code != 200:
                raise GitHubAPIError(
                    f"Failed to fetch PR files for {owner}/{repo}#{pull_number} "
                    f"({response.status_code}): {response.text[:300]}"
                )

            page_data = response.json()
            for item in page_data:
                files.append(PRFile(
                    filename=item["filename"],
                    status=item["status"],
                    patch=item.get("patch"),  # absent for binary/oversized files
                ))

            next_link = response.links.get("next")
            next_url = next_link["url"] if next_link else None
            next_params = None  # next URL already has query params baked in

        return files
    finally:
        if owns_client:
            client.close()


# Doc-file heuristic mirrors what app/agents/graph.py's static_analysis_node
# already assumes ("both analyzers are Python-specific" and separately, the
# triage node's is_doc_file skip) -- kept here as the single place that
# decides it from a raw filename, rather than duplicating the heuristic at
# every call site.
_DOC_EXTENSIONS = (".md", ".rst", ".txt")


def is_doc_file(filename: str) -> bool:
    return filename.lower().endswith(_DOC_EXTENSIONS)


def is_test_file(filename: str) -> bool:
    lower = filename.lower()
    return "test_" in lower or "/tests/" in lower or lower.startswith("tests/")


def post_pr_review_comment(
    owner: str,
    repo: str,
    pull_number: int,
    body: str,
    installation_token: str,
    *,
    client: httpx.Client | None = None,
) -> None:
    """
    Posts the final markdown review summary back to the GitHub Pull Request as a comment.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0)
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pull_number}/comments"

    try:
        response = client.post(url, headers=headers, json={"body": body})
        if response.status_code != 201:
            raise GitHubAPIError(
                f"Failed to post PR review comment to {owner}/{repo}#{pull_number} "
                f"({response.status_code}): {response.text[:300]}"
            )
    finally:
        if owns_client:
            client.close()
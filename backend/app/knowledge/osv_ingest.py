"""
Ingests OSV ecosystem zip files into the KnowledgeDocument table.

This hits the Google Cloud Storage bucket containing OSV JSON exports.
(e.g., `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`)
and unzips it in-memory to parse the OSV records.
"""
from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass

import httpx

OSV_BUCKET_BASE = "https://osv-vulnerabilities.storage.googleapis.com"


@dataclass
class IngestedAdvisory:
    osv_id: str
    summary: str
    description: str
    cwe_ids: list[str]
    severity: str
    url: str


class OSVIngestError(RuntimeError):
    pass


def fetch_advisories(
    *,
    ecosystem: str | None = None,
    client: httpx.Client | None = None,
) -> list[IngestedAdvisory]:
    """
    Fetch advisories from OSV bulk zip for a given ecosystem.
    If no ecosystem is provided, defaults to PyPI for demonstration.
    """
    if not ecosystem:
        ecosystem = "PyPI"

    owns_client = client is None
    client = client or httpx.Client(timeout=60.0)

    url = f"{OSV_BUCKET_BASE}/{ecosystem}/all.zip"
    advisories: list[IngestedAdvisory] = []

    try:
        response = client.get(url)
        if response.status_code == 404:
            raise OSVIngestError(f"Ecosystem {ecosystem} not found in OSV bucket.")
        if response.status_code != 200:
            raise OSVIngestError(f"Failed to fetch OSV zip for {ecosystem}: {response.status_code}")

        # Process the zip file in memory
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            for filename in z.namelist():
                if not filename.endswith(".json"):
                    continue

                with z.open(filename) as f:
                    data = json.load(f)

                osv_id = data.get("id", "")
                summary = data.get("summary", "")
                description = data.get("details", "")

                # Extract CWEs from aliases or database_specific if present
                cwes = []
                if "aliases" in data:
                    cwes.extend([a for a in data["aliases"] if a.startswith("CWE-")])
                
                # Sometime OSV puts CWEs in database_specific or affected ranges
                # For simplicity, we just use the ones in aliases, or GHSA IDs which map to CWEs elsewhere.
                # In OSV schema, CWEs might also be under `database_specific.cwe_ids` depending on the ecosystem.
                db_specific = data.get("database_specific", {})
                if "cwes" in db_specific:
                    for cwe in db_specific["cwes"]:
                        if cwe.get("cweId"):
                            cwes.append(cwe["cweId"])
                
                # Determine severity (CVSS) if available
                severity = "unknown"
                for metric in data.get("severity", []):
                    if metric.get("type") in ["CVSS_V3", "CVSS_V2"]:
                        score = metric.get("score", "")
                        # simplistic parsing of vector to get severity if we wanted, 
                        # but OSV doesn't explicitly store baseSeverity string often.
                        # For this stub, we extract it if possible, else leave unknown.
                        severity = "high" # default to high for now if a CVSS exists
                        break
                        
                # Some OSV records have database_specific severity
                if severity == "unknown" and "severity" in db_specific:
                    if isinstance(db_specific["severity"], str):
                        severity = db_specific["severity"].lower()

                # Get a reference URL
                url = ""
                for ref in data.get("references", []):
                    if ref.get("type") in ["ADVISORY", "WEB"]:
                        url = ref.get("url", "")
                        break
                
                if not url:
                    url = f"https://osv.dev/vulnerability/{osv_id}"

                advisories.append(
                    IngestedAdvisory(
                        osv_id=osv_id,
                        summary=summary or osv_id,
                        description=description or summary,
                        cwe_ids=list(set(cwes)),
                        severity=severity,
                        url=url,
                    )
                )

        return advisories
    finally:
        if owns_client:
            client.close()


def advisories_to_knowledge_documents(advisories: list[IngestedAdvisory]) -> list[dict]:
    """Shape ingested advisories into rows ready for KnowledgeDocument insertion."""
    docs = []
    for adv in advisories:
        docs.append({
            "source": "osv",
            "external_id": adv.osv_id,
            "title": adv.summary or adv.osv_id,
            "content": adv.description,
            "cwe_ids": ",".join(adv.cwe_ids) if adv.cwe_ids else None,
            "url": adv.url,
        })
    return docs

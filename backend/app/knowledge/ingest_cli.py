"""
CLI: pull real GitHub Security Advisories and upsert them into the
KnowledgeDocument table, deduplicated by (source, external_id).

Usage:
    PYTHONPATH=backend python3 backend/app/knowledge/ingest_cli.py \
        --ecosystems pip npm --pages 2 --token $GITHUB_TOKEN

Idempotent: running it again updates existing rows (by GHSA ID) rather than
duplicating them, so this is safe to run on a schedule (a cron job / RQ
periodic task in production, per the README's "Periodic Knowledge Sync"
background job).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db.models import KnowledgeDocument  # noqa: E402
from app.db.session import SessionLocal, init_db  # noqa: E402
from app.knowledge import ghsa_ingest, nvd_ingest, osv_ingest  # noqa: E402


def upsert_documents(db: Session, docs: list[dict]) -> tuple[int, int]:
    """
    Returns (n_created, n_updated).

    Two defenses against duplicate rows, because GitHub's /advisories
    endpoint has no stable sort key -- paginating a live, constantly-updated
    dataset can return the same advisory on more than one page within a
    single ingestion run:

    1. Deduplicate the incoming batch itself by (source, external_id) before
       writing anything, keeping the last occurrence.
    2. db.flush() after every write. SessionLocal is configured with
       autoflush=False (deliberately, for read-heavy request-handling code
       elsewhere in this project), which means a SELECT run later in the
       same loop iteration would NOT see an INSERT from earlier in that
       same loop unless explicitly flushed -- that was the actual root
       cause of duplicate rows found in production data (3x copies of
       GHSA-g6g7-pvmx-m74p from a single `--ecosystems pip npm` run).

    The UniqueConstraint on KnowledgeDocument(source, external_id) is the
    real backstop underneath both of these -- even if a future caller
    reintroduces this bug, the database itself now refuses the duplicate
    insert rather than silently accepting it.
    """
    deduped: dict[tuple[str, str], dict] = {}
    for doc in docs:
        deduped[(doc["source"], doc["external_id"])] = doc

    created, updated = 0, 0
    for doc in deduped.values():
        existing = db.scalar(
            select(KnowledgeDocument).where(
                KnowledgeDocument.source == doc["source"],
                KnowledgeDocument.external_id == doc["external_id"],
            )
        )
        if existing:
            existing.title = doc["title"]
            existing.content = doc["content"]
            existing.cwe_ids = doc["cwe_ids"]
            existing.url = doc["url"]
            updated += 1
        else:
            db.add(KnowledgeDocument(
                source=doc["source"],
                external_id=doc["external_id"],
                title=doc["title"],
                content=doc["content"],
                cwe_ids=doc["cwe_ids"],
                url=doc["url"],
            ))
            created += 1
        db.flush()  # make this write visible to the next iteration's SELECT
    db.commit()
    return created, updated


def run_ingestion(sources: list[str], ecosystems: list[str], pages: int, token: str | None, nvd_api_key: str | None) -> None:
    init_db()
    db = SessionLocal()
    total_created, total_updated = 0, 0
    try:
        for source in sources:
            print(f"--- Ingesting from {source.upper()} ---")
            for ecosystem in ecosystems:
                print(f"Fetching {source.upper()} advisories for ecosystem={ecosystem}...")
                advisories = []
                docs = []
                
                if source == "ghsa":
                    advisories = ghsa_ingest.fetch_advisories(
                        ecosystem=ecosystem, max_pages=pages, github_token=token,
                    )
                    docs = ghsa_ingest.advisories_to_knowledge_documents(advisories)
                elif source == "nvd":
                    advisories = nvd_ingest.fetch_advisories(
                        ecosystem=ecosystem, max_pages=pages, api_key=nvd_api_key, per_page=100,
                    )
                    docs = nvd_ingest.advisories_to_knowledge_documents(advisories)
                elif source == "osv":
                    advisories = osv_ingest.fetch_advisories(ecosystem=ecosystem)
                    docs = osv_ingest.advisories_to_knowledge_documents(advisories)
                else:
                    print(f"Unknown source: {source}")
                    continue
                    
                created, updated = upsert_documents(db, docs)
                total_created += created
                total_updated += updated
                print(f"  {ecosystem} ({source}): {len(advisories)} fetched, {created} created, {updated} updated")
    finally:
        db.close()
    print(f"Done. {total_created} new documents, {total_updated} updated.")


def main():
    parser = argparse.ArgumentParser(description="Ingest real advisories into KnowledgeDocument")
    parser.add_argument("--sources", nargs="+", choices=["ghsa", "nvd", "osv"], default=["ghsa"])
    parser.add_argument("--ecosystems", nargs="+", default=["pip"])
    parser.add_argument("--pages", type=int, default=2)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--nvd-token", default=os.environ.get("NVD_API_KEY"))
    args = parser.parse_args()
    run_ingestion(args.sources, args.ecosystems, args.pages, args.token, args.nvd_token)


if __name__ == "__main__":
    main()

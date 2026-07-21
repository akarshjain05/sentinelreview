"""
Seeds the local SQLite DB with realistic sample data so the dashboard has
something real to render during development, without needing a live GitHub
App connection. Safe to run repeatedly -- clears and re-seeds rather than
accumulating duplicates.

Usage:
    DATABASE_URL="sqlite:///./dev.db" PYTHONPATH=backend python3 scripts/seed_dashboard_data.py
"""
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.db.models import (  # noqa: E402
    AgentName,
    AgentRun,
    Base,
    Finding,
    Installation,
    KnowledgeDocument,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
    Severity,
)
from app.db.session import SessionLocal, engine  # noqa: E402


def seed() -> None:
    Base.metadata.create_all(engine)
    db = SessionLocal()

    # Clear existing data for idempotent re-seeding.
    for model in [AgentRun, Finding, Review, PullRequest, Repository, Installation, KnowledgeDocument]:
        db.query(model).delete()
    db.commit()

    inst = Installation(id=str(uuid.uuid4()), github_installation_id=1001, account_login="akarsh")
    db.add(inst)
    db.flush()

    repo = Repository(
        id=str(uuid.uuid4()), installation_id=inst.id, github_repo_id=5001,
        full_name="akarsh/sentinelreview", default_branch="main",
    )
    db.add(repo)
    db.flush()

    # A real KnowledgeDocument row -- same content as the actual seed
    # corpus (app/knowledge/seed_corpus.py's CWE-89 entry) -- so the
    # dashboard's citation feature (Review Detail's "Grounded in" section)
    # has something real to resolve and display, not an empty state.
    db.add(KnowledgeDocument(
        id=str(uuid.uuid4()), source="cwe", external_id="CWE-89",
        title="CWE-89: SQL Injection",
        content=(
            "Occurs when untrusted input is concatenated directly into a SQL query "
            "string instead of being passed as a bound parameter."
        ),
        url=None,
    ))
    db.flush()

    now = datetime.now(timezone.utc)

    # Review 1: a real-shaped result -- SQL injection + hardcoded secret,
    # mirroring exactly what the actual Bandit+Semgrep pipeline produces
    # against evaluation/fixtures/python_vuln_benchmark.py's sqli-01 and
    # secret-01 cases.
    pr1 = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=42, title="Add user search endpoint",
        head_sha="a1b2c3d", base_sha="e4f5g6h", author_login="akarsh",
    )
    db.add(pr1)
    db.flush()
    review1 = Review(
        id=str(uuid.uuid4()), pull_request_id=pr1.id, triggered_sha="a1b2c3d",
        status=ReviewStatus.COMPLETED, started_at=now - timedelta(minutes=12),
        completed_at=now - timedelta(minutes=12) + timedelta(seconds=3),
        total_latency_ms=2890,
    )
    db.add(review1)
    db.flush()
    db.add(Finding(
        id=str(uuid.uuid4()), review_id=review1.id, file_path="app/search.py",
        start_line=14, end_line=14, cwe_id="CWE-89", vulnerability_type="sql_injection",
        severity=Severity.HIGH, confidence=0.9, source="bandit+semgrep+classifier",
        explanation="Detected pattern consistent with CWE-89 (static analyzer confidence 0.90). "
                     "Classifier corroborates with 0.82 confidence on the matching label "
                     "'sql_injection'.",
        code_snippet='cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        cited_document_ids="CWE-89",
    ))
    db.add(Finding(
        id=str(uuid.uuid4()), review_id=review1.id, file_path="app/config.py",
        start_line=3, end_line=3, cwe_id="CWE-798", vulnerability_type="hardcoded_secret",
        severity=Severity.MEDIUM, confidence=0.7, source="semgrep+classifier",
        explanation="Detected pattern consistent with CWE-798 (static analyzer confidence 0.70). "
                     "Classifier assigned 0.45 confidence to the matching label 'hardcoded_secret' "
                     "(below high-confidence threshold).",
        code_snippet='API_KEY = "sk_live_51H8f9aZ2xJmklsdf902"',
    ))

    # Real-shaped AgentRun rows -- latencies roughly match what this
    # project actually measured for the real pipeline (see README:
    # Bandit+Semgrep ~2.6-3.2s dominated by static_analysis; other stages
    # are fast). The seed script inserts Finding rows directly rather than
    # running the real pipeline, so without this, the Observability page
    # would show an empty state against seed data alone.
    for agent_name, latency_ms in [
        (AgentName.TRIAGE, 8),
        (AgentName.STATIC_ANALYSIS, 2810),
        (AgentName.RETRIEVAL, 45),
        (AgentName.CLASSIFICATION, 15),
        (AgentName.FIX_SUGGESTION, 3),
        (AgentName.VERIFICATION, 2),
        (AgentName.REPORTING, 7),
    ]:
        db.add(AgentRun(
            id=str(uuid.uuid4()), review_id=review1.id, agent_name=agent_name,
            latency_ms=latency_ms, succeeded=True,
        ))
    db.commit()

    # Review 2: clean PR, no findings.
    pr2 = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=41, title="Fix typo in README",
        head_sha="b2c3d4e", base_sha="e4f5g6h", author_login="akarsh",
    )
    db.add(pr2)
    db.flush()
    review2 = Review(
        id=str(uuid.uuid4()), pull_request_id=pr2.id, triggered_sha="b2c3d4e",
        status=ReviewStatus.COMPLETED, started_at=now - timedelta(hours=3),
        completed_at=now - timedelta(hours=3) + timedelta(seconds=2),
        total_latency_ms=1120,
    )
    db.add(review2)
    db.commit()

    # Review 3: currently running (no findings/completion yet), to exercise the "running" status in the UI.
    pr3 = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=43, title="Refactor auth middleware",
        head_sha="c3d4e5f", base_sha="e4f5g6h", author_login="akarsh",
    )
    db.add(pr3)
    db.flush()
    review3 = Review(
        id=str(uuid.uuid4()), pull_request_id=pr3.id, triggered_sha="c3d4e5f",
        status=ReviewStatus.RUNNING, started_at=now - timedelta(seconds=8),
    )
    db.add(review3)
    db.commit()

    db.close()
    print(f"Seeded 1 installation, 1 repository, 3 pull requests, 3 reviews, 2 findings into {engine.url}")


if __name__ == "__main__":
    seed()
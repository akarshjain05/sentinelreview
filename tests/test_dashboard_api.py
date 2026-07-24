import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import (
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
from app.db.session import get_db
from app.jobs.queue import get_review_queue
from app.main import app


@pytest.fixture
def db_session():
    # StaticPool + check_same_thread=False: sqlite:///:memory: normally
    # hands out a brand-new, empty in-memory database on every connection
    # checkout from the pool -- fine for a single unpooled connection, but
    # FastAPI's TestClient and this fixture's own setup code checkout
    # connections independently, so without StaticPool forcing them all
    # through the SAME underlying connection, requests would query a
    # different (tableless) database than the one Base.metadata.create_all
    # and the test's own seeding actually populated. This is the standard
    # documented pattern for testing a FastAPI app against in-memory SQLite.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def client(db_session, fake_queue):
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_review_queue] = lambda: fake_queue
    yield TestClient(app)
    app.dependency_overrides.clear()


def _seed_review_with_findings(db) -> str:
    inst = Installation(id=str(uuid.uuid4()), github_installation_id=1, account_login="akarsh")
    db.add(inst)
    db.flush()
    repo = Repository(id=str(uuid.uuid4()), installation_id=inst.id, github_repo_id=1, full_name="akarsh/sentinelreview")
    db.add(repo)
    db.flush()
    pr = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=42, title="Add search endpoint",
        head_sha="abc123", base_sha="def456", author_login="akarsh",
    )
    db.add(pr)
    db.flush()
    review = Review(id=str(uuid.uuid4()), pull_request_id=pr.id, triggered_sha="abc123", status=ReviewStatus.COMPLETED)
    db.add(review)
    db.flush()
    db.add(Finding(
        id=str(uuid.uuid4()), review_id=review.id, file_path="app/search.py",
        start_line=10, end_line=10, cwe_id="CWE-89", vulnerability_type="sql_injection",
        severity=Severity.HIGH, confidence=0.9, source="bandit+semgrep",
        explanation="SQL injection via string concatenation.", code_snippet="cursor.execute(...)",
    ))
    db.add(Finding(
        id=str(uuid.uuid4()), review_id=review.id, file_path="app/config.py",
        start_line=3, end_line=3, cwe_id="CWE-798", vulnerability_type="hardcoded_secret",
        severity=Severity.MEDIUM, confidence=0.7, source="semgrep",
        explanation="Hardcoded API key.", code_snippet='API_KEY = "..."',
    ))
    db.commit()
    return review.id


def test_list_reviews_empty(client):
    response = client.get("/reviews")
    assert response.status_code == 200
    assert response.json() == []


def test_list_reviews_returns_summary_with_severity_counts(client, db_session):
    _seed_review_with_findings(db_session)

    response = client.get("/reviews")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["repo_full_name"] == "akarsh/sentinelreview"
    assert data[0]["pr_number"] == 42
    assert data[0]["finding_count"] == 2
    assert data[0]["severity_counts"]["high"] == 1
    assert data[0]["severity_counts"]["medium"] == 1
    assert data[0]["severity_counts"]["critical"] == 0


def test_get_review_detail_includes_full_findings(client, db_session):
    review_id = _seed_review_with_findings(db_session)

    response = client.get(f"/reviews/{review_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["pr_title"] == "Add search endpoint"
    assert len(data["findings"]) == 2
    cwes = {f["cwe_id"] for f in data["findings"]}
    assert cwes == {"CWE-89", "CWE-798"}
    sqli = next(f for f in data["findings"] if f["cwe_id"] == "CWE-89")
    assert sqli["source"] == "bandit+semgrep"
    assert sqli["file_path"] == "app/search.py"


def test_get_review_detail_404_for_missing_review(client):
    response = client.get("/reviews/does-not-exist")
    assert response.status_code == 404


def test_evaluation_endpoint_404_when_no_results_exist(client, tmp_path, monkeypatch):
    import app.routers.evaluation as eval_router
    monkeypatch.setattr(eval_router, "_EVAL_DIR", tmp_path)

    response = client.get("/evaluation/latest")
    assert response.status_code == 404


def test_evaluation_endpoint_returns_real_result_file_contents(client, tmp_path, monkeypatch):
    import app.routers.evaluation as eval_router
    monkeypatch.setattr(eval_router, "_EVAL_DIR", tmp_path)

    sample = {"results": [], "metrics": {"precision": 0.909, "recall": 1.0, "f1": 0.952}}
    (tmp_path / "results_merged.json").write_text(json.dumps(sample))

    response = client.get("/evaluation/latest")
    assert response.status_code == 200
    data = response.json()
    assert "merged" in data
    assert data["merged"]["metrics"]["recall"] == 1.0
    assert "bandit_only" not in data  # only files that actually exist should appear


def test_get_review_detail_resolves_real_citations(client, db_session):
    """
    A finding's cited_document_ids ("CWE-89") should resolve to the actual
    KnowledgeDocument it references (title, source, url) -- not just be
    echoed back as a bare ID string the frontend can't do anything useful
    with. Real data flow: seed a real KnowledgeDocument, cite it from a
    real Finding, confirm the API actually joins them.
    """
    db_session.add(KnowledgeDocument(
        id=str(uuid.uuid4()), source="cwe", external_id="CWE-89",
        title="CWE-89: SQL Injection", content="...", url=None,
    ))
    review_id = _seed_review_with_findings(db_session)
    # _seed_review_with_findings already creates a CWE-89 finding; attach the citation to it.
    finding = db_session.query(Finding).filter_by(review_id=review_id, cwe_id="CWE-89").one()
    finding.cited_document_ids = "CWE-89"
    db_session.commit()

    response = client.get(f"/reviews/{review_id}")
    data = response.json()
    sqli_finding = next(f for f in data["findings"] if f["cwe_id"] == "CWE-89")

    assert len(sqli_finding["citations"]) == 1
    assert sqli_finding["citations"][0]["external_id"] == "CWE-89"
    assert sqli_finding["citations"][0]["title"] == "CWE-89: SQL Injection"
    assert sqli_finding["citations"][0]["source"] == "cwe"


def test_get_review_detail_empty_citations_when_none_cited(client, db_session):
    review_id = _seed_review_with_findings(db_session)
    response = client.get(f"/reviews/{review_id}")
    data = response.json()
    assert all(f["citations"] == [] for f in data["findings"])


def test_rerun_creates_new_review_and_enqueues_it(client, db_session, fake_queue):
    original_id = _seed_review_with_findings(db_session)
    original = db_session.get(Review, original_id)

    response = client.post(f"/reviews/{original_id}/rerun")
    assert response.status_code == 200
    data = response.json()

    new_review_id = data["review_id"]
    assert new_review_id != original_id  # a NEW review, not the original mutated in place

    new_review = db_session.get(Review, new_review_id)
    assert new_review.pull_request_id == original.pull_request_id
    assert new_review.status == ReviewStatus.QUEUED
    assert new_review.is_manual_rerun is True

    # The original review's own findings/history are untouched.
    original_refetched = db_session.get(Review, original_id)
    assert len(original_refetched.findings) == 2

    assert len(fake_queue.enqueued) == 1
    _func, args, _kwargs = fake_queue.enqueued[0]
    assert args == (new_review_id,)


def test_rerun_404_for_missing_review(client):
    response = client.post("/reviews/does-not-exist/rerun")
    assert response.status_code == 404


def test_list_repositories(client, db_session):
    _seed_review_with_findings(db_session)
    response = client.get("/repositories")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["full_name"] == "akarsh/sentinelreview"
    assert data[0]["review_count"] == 1


def test_list_reviews_with_repo_filter(client, db_session):
    _seed_review_with_findings(db_session)
    
    # Matching repo
    response = client.get("/reviews?repo=akarsh/sentinelreview")
    assert response.status_code == 200
    assert len(response.json()) == 1

    # Non-matching repo
    response = client.get("/reviews?repo=akarsh/other-repo")
    assert response.status_code == 200
    assert len(response.json()) == 0
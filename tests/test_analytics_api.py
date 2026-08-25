from datetime import datetime

import pytest
from app.db.models import (
    Base,
    Finding,
    Installation,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
    Severity,
)
from app.db.session import get_db
from app.jobs.queue import get_review_queue
from app.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionClass = sessionmaker(bind=engine)
    session = SessionClass()
    yield session
    session.close()

@pytest.fixture
def client(db_session, fake_queue):
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_review_queue] = lambda: fake_queue
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_get_dashboard_stats(client: TestClient, db_session: Session):
    # Setup test data
    inst = Installation(
        id="inst_1",
        github_installation_id=1,
        account_login="testorg"
    )
    db_session.add(inst)
    db_session.flush()

    repo = Repository(
        id="repo_1",
        installation_id=inst.id,
        github_repo_id=1001,
        full_name="testorg/repo1"
    )
    db_session.add(repo)
    db_session.flush()

    pr = PullRequest(
        id="pr_1",
        repository_id=repo.id,
        number=1,
        title="Test PR",
        head_sha="head",
        base_sha="base",
        author_login="user"
    )
    db_session.add(pr)
    db_session.flush()

    from datetime import timezone
    dt = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
    
    rev = Review(
        id="rev_1",
        pull_request_id=pr.id,
        triggered_sha="head",
        status=ReviewStatus.COMPLETED,
        completed_at=dt,
        total_latency_ms=10000,
        total_cost_usd=0.05
    )
    db_session.add(rev)
    db_session.flush()

    f1 = Finding(
        id="f1",
        review_id=rev.id,
        severity=Severity.HIGH,
        vulnerability_type="sql_injection",
        file_path="foo.py",
        start_line=1,
        end_line=2,
        explanation="bad",
        confidence=0.9,
        source="semgrep",
        code_snippet="print('bad')"
    )
    f2 = Finding(
        id="f2",
        review_id=rev.id,
        severity=Severity.CRITICAL,
        vulnerability_type="rce",
        file_path="bar.py",
        start_line=1,
        end_line=2,
        explanation="worse",
        confidence=0.99,
        source="semgrep",
        code_snippet="eval('worse')"
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    response = client.get(
        "/observability/dashboard",
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": [1]}'}
    )
    assert response.status_code == 200
    data = response.json()
    
    assert len(data["findings_by_severity"]) == 2
    # Ensure they match what we added
    severities = {item["severity"]: item["count"] for item in data["findings_by_severity"]}
    assert severities["high"] == 1
    assert severities["critical"] == 1

    assert len(data["findings_over_time"]) == 1
    assert data["findings_over_time"][0]["date"] == "2026-07-20"
    assert data["findings_over_time"][0]["count"] == 2

    assert len(data["reviews_over_time"]) == 1
    assert data["reviews_over_time"][0]["date"] == "2026-07-20"
    assert data["reviews_over_time"][0]["avg_latency_ms"] == 10000
    assert data["reviews_over_time"][0]["total_cost_usd"] == 0.05
    assert data["reviews_over_time"][0]["review_count"] == 1

def test_get_dashboard_stats_unauthorized_empty(client: TestClient, db_session: Session):
    response = client.get(
        "/observability/dashboard",
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": [999]}'}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["findings_by_severity"] == []
    assert data["findings_over_time"] == []
    assert data["reviews_over_time"] == []

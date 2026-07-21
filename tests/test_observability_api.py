import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import (
    AgentName,
    AgentRun,
    Base,
    Installation,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
)
from app.db.session import get_db
from app.main import app


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    yield TestClient(app)
    app.dependency_overrides.clear()


def _seed_review_with_agent_runs(db, *, latencies: dict) -> str:
    """latencies: {agent_name: [(latency_ms, succeeded), ...]}"""
    # Random IDs, not hardcoded 1s: this helper is called more than once
    # per test in the multi-review aggregation test, and github_installation_id/
    # github_repo_id both have UNIQUE constraints -- hardcoding them caused
    # a real IntegrityError on the second call.
    unique_suffix = uuid.uuid4().int % 1_000_000

    inst = Installation(
        id=str(uuid.uuid4()), github_installation_id=unique_suffix, account_login="akarsh",
    )
    db.add(inst)
    db.flush()
    repo = Repository(
        id=str(uuid.uuid4()), installation_id=inst.id, github_repo_id=unique_suffix, full_name="akarsh/x",
    )
    db.add(repo)
    db.flush()
    pr = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=1, title="t",
        head_sha="a", base_sha="b", author_login="akarsh",
    )
    db.add(pr)
    db.flush()
    review = Review(
        id=str(uuid.uuid4()), pull_request_id=pr.id, triggered_sha="a",
        status=ReviewStatus.COMPLETED, total_latency_ms=sum(
            lat for runs in latencies.values() for lat, _ in runs
        ),
    )
    db.add(review)
    db.flush()

    for agent_name, runs in latencies.items():
        for latency_ms, succeeded in runs:
            db.add(AgentRun(
                id=str(uuid.uuid4()), review_id=review.id, agent_name=agent_name,
                latency_ms=latency_ms, succeeded=succeeded, cost_usd=0.0,
            ))
    db.commit()
    return review.id


def test_latency_stats_empty_when_no_data(client):
    response = client.get("/observability/latency")
    assert response.status_code == 200
    data = response.json()
    assert data["per_agent"] == []
    assert data["total_reviews"] == 0


def test_latency_stats_computes_real_averages_per_agent(client, db_session):
    _seed_review_with_agent_runs(db_session, latencies={
        AgentName.STATIC_ANALYSIS: [(100, True), (200, True), (300, True)],
        AgentName.TRIAGE: [(10, True)],
    })

    response = client.get("/observability/latency")
    data = response.json()

    static_analysis_stats = next(a for a in data["per_agent"] if a["agent_name"] == "static_analysis")
    assert static_analysis_stats["run_count"] == 3
    assert static_analysis_stats["avg_latency_ms"] == 200.0
    assert static_analysis_stats["min_latency_ms"] == 100
    assert static_analysis_stats["max_latency_ms"] == 300
    assert static_analysis_stats["success_rate"] == 1.0


def test_latency_stats_computes_real_success_rate_with_failures(client, db_session):
    _seed_review_with_agent_runs(db_session, latencies={
        AgentName.RETRIEVAL: [(50, True), (60, True), (999, False)],
    })

    response = client.get("/observability/latency")
    data = response.json()

    retrieval_stats = next(a for a in data["per_agent"] if a["agent_name"] == "retrieval")
    assert retrieval_stats["run_count"] == 3
    assert retrieval_stats["success_rate"] == round(2 / 3, 3)


def test_latency_stats_includes_honest_cost_tracking_note(client, db_session):
    _seed_review_with_agent_runs(db_session, latencies={AgentName.TRIAGE: [(10, True)]})

    response = client.get("/observability/latency")
    data = response.json()

    assert data["total_cost_usd"] == 0.0
    assert "not yet populated" in data["cost_tracking_note"]


def test_latency_stats_aggregates_across_multiple_reviews(client, db_session):
    """Two separate reviews' AgentRun rows for the same agent should combine into one aggregate, not two."""
    _seed_review_with_agent_runs(db_session, latencies={AgentName.CLASSIFICATION: [(100, True)]})
    _seed_review_with_agent_runs(db_session, latencies={AgentName.CLASSIFICATION: [(300, True)]})

    response = client.get("/observability/latency")
    data = response.json()

    classification_stats = next(a for a in data["per_agent"] if a["agent_name"] == "classification")
    assert classification_stats["run_count"] == 2
    assert classification_stats["avg_latency_ms"] == 200.0
    assert data["total_reviews"] == 2


def test_latency_stats_returns_agents_in_real_pipeline_execution_order(client, db_session):
    """
    Regression test for a real UX bug found via screenshot review: the
    endpoint originally sorted per_agent alphabetically (classification,
    fix_suggestion, reporting, retrieval, static_analysis, triage,
    verification), which scrambles the actual pipeline sequence and makes
    a latency dashboard much harder to read top-to-bottom. Fixed to sort
    by real execution order instead, reusing pipeline_runner.py's own
    node-to-agent mapping as the single source of truth for that order
    rather than defining a second, driftable list.
    """
    # Seed all 7 agents in a deliberately scrambled (reverse-alphabetical)
    # insertion order, so a passing test can't be explained by coincidence
    # -- if the endpoint just echoed insertion or DB order, this would fail.
    _seed_review_with_agent_runs(db_session, latencies={
        AgentName.VERIFICATION: [(2, True)],
        AgentName.TRIAGE: [(8, True)],
        AgentName.STATIC_ANALYSIS: [(2810, True)],
        AgentName.RETRIEVAL: [(45, True)],
        AgentName.REPORTING: [(7, True)],
        AgentName.FIX_SUGGESTION: [(3, True)],
        AgentName.CLASSIFICATION: [(15, True)],
    })

    response = client.get("/observability/latency")
    data = response.json()

    agent_order = [a["agent_name"] for a in data["per_agent"]]
    assert agent_order == [
        "triage", "static_analysis", "retrieval", "classification",
        "fix_suggestion", "verification", "reporting",
    ]
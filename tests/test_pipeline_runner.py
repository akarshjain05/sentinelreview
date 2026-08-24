import uuid

import pytest
from app.agents.graph import build_graph
from app.agents.state import ChangedFile, ReviewState
from app.db.models import (
    Base,
    Installation,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
)
from app.sandbox.analyzers import MockStaticAnalyzer
from app.services.pipeline_runner import run_review_with_observability
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/observability_test.db")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _seed_review(db) -> str:
    inst = Installation(id=str(uuid.uuid4()), github_installation_id=1, account_login="akarsh")
    db.add(inst)
    db.flush()
    repo = Repository(id=str(uuid.uuid4()), installation_id=inst.id, github_repo_id=1, full_name="akarsh/test")
    db.add(repo)
    db.flush()
    pr = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=1, title="t",
        head_sha="a", base_sha="b", author_login="akarsh",
    )
    db.add(pr)
    db.flush()
    review = Review(id=str(uuid.uuid4()), pull_request_id=pr.id, triggered_sha="a", status=ReviewStatus.QUEUED)
    db.add(review)
    db.commit()
    return review.id


def test_pipeline_run_writes_real_agent_run_rows(db_session):
    review_id = _seed_review(db_session)

    state = ReviewState(
        repo_full_name="akarsh/test",
        pr_number=1,
        pr_title="Add search",
        pr_body="Adds search endpoint",
        head_sha="a",
        changed_files=[
            ChangedFile(path="app.py", diff="+ import subprocess\n+ subprocess.call(x, shell=True)\n"),
        ],
    )

    fast_graph = build_graph(static_analyzers={"mock": MockStaticAnalyzer()})
    run_review_with_observability(state, db=db_session, review_id=review_id, graph=fast_graph)

    from app.db.models import AgentRun
    runs = db_session.query(AgentRun).filter_by(review_id=review_id).all()

    # All 7 pipeline stages should have written a real row.
    agent_names = {r.agent_name for r in runs}
    assert len(runs) == 7
    assert {"triage", "static_analysis", "retrieval", "classification",
            "fix_suggestion", "verification", "reporting"} <= {a.value for a in agent_names}

    # Every row should have a real (non-negative) latency captured.
    assert all(r.latency_ms is not None and r.latency_ms >= 0 for r in runs)

    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.COMPLETED
    assert review.total_latency_ms >= 0


def test_pipeline_run_marks_review_failed_on_missing_review(db_session):
    state = ReviewState(
        repo_full_name="akarsh/test", pr_number=1, pr_title="t", pr_body="b", head_sha="a",
    )
    with pytest.raises(ValueError):
        run_review_with_observability(state, db=db_session, review_id="does-not-exist")


def test_pipeline_run_persists_finding_rows_to_db(db_session):
    """
    Regression test for a real, previously-hidden bug: findings only ever
    lived in the in-memory final_state dict returned by
    run_review_with_observability, never written to the `findings` table.
    Every review run through this function for real would show zero
    findings in the dashboard regardless of what the pipeline actually
    detected -- caught by tests/test_review_worker.py's end-to-end test,
    not by this file's existing tests (they checked AgentRun rows and the
    return value, never DB-persisted Finding rows).
    """
    from app.db.models import Finding

    review_id = _seed_review(db_session)

    state = ReviewState(
        repo_full_name="akarsh/x",
        pr_number=1,
        pr_title="Add search",
        pr_body="adds search endpoint",
        head_sha="a",
        changed_files=[
            ChangedFile(path="app/search.py", diff="+ import subprocess\n+ subprocess.call(x, shell=True)\n"),
        ],
    )

    run_review_with_observability(state, db=db_session, review_id=review_id)

    findings = db_session.query(Finding).filter_by(review_id=review_id).all()
    assert len(findings) >= 1
    assert any(f.cwe_id == "CWE-78" for f in findings)
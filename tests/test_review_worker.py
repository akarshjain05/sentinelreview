import uuid

import httpx
import pytest
import respx
from app.core.config import get_settings
from app.db.models import (
    AgentRun,
    Base,
    Installation,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
)
from app.jobs.review_worker import run_review_job
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # run_review_job opens its OWN session via SessionLocal (matching how a
    # real separate worker process has to work), so point that at the same
    # in-memory engine this fixture uses -- otherwise the job would talk to
    # a completely different (tableless) database. Patched on
    # app.jobs.review_worker specifically, not app.db.session: that module
    # did `from app.db.session import SessionLocal`, which creates its own
    # independent binding at import time that patching the origin module
    # would not affect.
    import app.jobs.review_worker as review_worker_module
    monkeypatch.setattr(review_worker_module, "SessionLocal", Session)

    yield session
    session.close()


@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return private_pem


def _seed(db, *, with_installation=True) -> str:
    inst = None
    if with_installation:
        inst = Installation(id=str(uuid.uuid4()), github_installation_id=9001, account_login="akarsh")
        db.add(inst)
        db.flush()

    repo = Repository(
        id=str(uuid.uuid4()), installation_id=inst.id if inst else None,
        github_repo_id=5001, full_name="akarsh/sentinelreview",
    )
    db.add(repo)
    db.flush()
    pr = PullRequest(
        id=str(uuid.uuid4()), repository_id=repo.id, number=42, title="Add search endpoint",
        head_sha="abc123", base_sha="def456", author_login="akarsh",
    )
    db.add(pr)
    db.flush()
    review = Review(id=str(uuid.uuid4()), pull_request_id=pr.id, triggered_sha="abc123", status=ReviewStatus.QUEUED)
    db.add(review)
    db.commit()
    return review.id


def test_job_fails_cleanly_when_review_not_found(db_session):
    from app.jobs.review_worker import ReviewJobError
    with pytest.raises(ReviewJobError, match="not found"):
        run_review_job("does-not-exist")


def test_job_marks_review_failed_when_repository_has_no_installation(db_session):
    review_id = _seed(db_session, with_installation=False)

    run_review_job(review_id)

    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.FAILED
    assert "no associated installation" in review.error_message


def test_job_marks_review_failed_when_github_app_unconfigured(db_session, monkeypatch):
    from app.core.config import Settings
    monkeypatch.setattr("app.core.config.get_settings", lambda: Settings(_env_file=None))

    review_id = _seed(db_session)

    run_review_job(review_id)

    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.FAILED
    assert "installation token" in review.error_message

    get_settings.cache_clear()


@respx.mock
def test_job_marks_review_failed_when_github_pr_files_fetch_errors(db_session, monkeypatch, rsa_keypair):
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_PRIVATE_KEY", rsa_keypair)
    get_settings.cache_clear()

    respx.post("https://api.github.com/app/installations/9001/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_test", "expires_at": "2026-08-01T00:00:00Z"})
    )
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )

    review_id = _seed(db_session)
    run_review_job(review_id)

    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.FAILED
    assert "Could not fetch PR files" in review.error_message

    get_settings.cache_clear()


@respx.mock
def test_job_runs_real_pipeline_end_to_end_and_detects_real_vulnerability(db_session, monkeypatch, rsa_keypair):
    """
    The actual point of this whole job: given a real (mocked-at-the-HTTP-boundary)
    GitHub PR containing a genuine SQL injection, the job should authenticate,
    fetch the diff, run the REAL Bandit+Semgrep pipeline against it, and
    persist a real Finding -- not a simulation of any of these steps.
    """
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_PRIVATE_KEY", rsa_keypair)
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    get_settings.cache_clear()

    respx.post("https://api.github.com/app/installations/9001/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_test", "expires_at": "2026-08-01T00:00:00Z"})
    )
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(200, json=[
            {
                "filename": "app/search.py",
                "status": "modified",
                "patch": '+cursor.execute("SELECT * FROM users WHERE name = " + name)\n',
            },
            {"filename": "README.md", "status": "modified", "patch": "+docs update\n"},
            {"filename": "assets/logo.png", "status": "added"},  # no patch -- must be skipped, not crash
        ])
    )
    respx.post("https://api.github.com/repos/akarsh/sentinelreview/issues/42/comments").mock(
        return_value=httpx.Response(201, json={})
    )

    review_id = _seed(db_session)
    run_review_job(review_id)

    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.COMPLETED
    assert len(review.findings) >= 1
    
    finding = next((f for f in review.findings if f.cwe_id == "CWE-89"), None)
    assert finding is not None
    
    # Verify patch suggestions and verification runs were persisted
    assert len(finding.patch_suggestions) >= 1
    patch = finding.patch_suggestions[0]
    assert patch.diff is not None
    assert patch.reasoning is not None
    
    assert len(patch.verification_runs) >= 1
    vr = patch.verification_runs[0]
    assert vr.issue_resolved is not None

    # Real observability: AgentRun rows for the full 7-stage pipeline.
    agent_runs = db_session.query(AgentRun).filter_by(review_id=review_id).all()
    assert len(agent_runs) == 7

    get_settings.cache_clear()
import hashlib
import hmac
import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.db.models import Base, Installation, PullRequest, Repository, Review
from app.db.session import get_db
from app.jobs.queue import get_review_queue
from app.main import app


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


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
def client(db_session, fake_queue, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_review_queue] = lambda: fake_queue
    yield TestClient(app)
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _post_webhook(client: TestClient, event: str, payload: dict) -> httpx.Response:
    body = json.dumps(payload).encode()
    signature = _sign("test-secret", body)
    return client.post(
        "/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": signature, "X-GitHub-Event": event},
    )


# ---- Signature verification (no DB access needed) --------------------------

def test_webhook_rejects_bad_signature(client):
    body = json.dumps({"action": "opened"}).encode()
    response = client.post(
        "/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "pull_request"},
    )
    assert response.status_code == 401


def test_webhook_ignores_unsupported_event(client):
    response = _post_webhook(client, "star", {"action": "created"})
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


# ---- Installation events ----------------------------------------------------

_INSTALLATION_PAYLOAD = {
    "action": "created",
    "installation": {"id": 9001, "account": {"login": "akarsh"}},
    "repositories": [
        {"id": 5001, "full_name": "akarsh/sentinelreview"},
        {"id": 5002, "full_name": "akarsh/mini-code-judge"},
    ],
}


def test_installation_webhook_creates_installation_and_repositories(client, db_session):
    response = _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)
    assert response.status_code == 200
    assert response.json()["status"] == "installation_synced"

    installation = db_session.query(Installation).filter_by(github_installation_id=9001).one()
    assert installation.account_login == "akarsh"
    repos = db_session.query(Repository).filter_by(installation_id=installation.id).all()
    assert {r.full_name for r in repos} == {"akarsh/sentinelreview", "akarsh/mini-code-judge"}


def test_installation_webhook_is_idempotent_on_redelivery(client, db_session):
    """GitHub can and does redeliver webhooks -- a second delivery must not create duplicate rows."""
    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)
    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)

    assert db_session.query(Installation).filter_by(github_installation_id=9001).count() == 1
    assert db_session.query(Repository).filter_by(github_repo_id=5001).count() == 1


def test_installation_webhook_deleted_removes_installation(client, db_session):
    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)

    response = _post_webhook(client, "installation", {
        "action": "deleted",
        "installation": {"id": 9001, "account": {"login": "akarsh"}},
    })
    assert response.status_code == 200
    assert response.json()["status"] == "installation_removed"
    assert db_session.query(Installation).filter_by(github_installation_id=9001).count() == 0


# ---- Pull request events ----------------------------------------------------

def _pr_payload(number=42, repo_id=5001, action="opened") -> dict:
    return {
        "action": action,
        "installation": {"id": 9001},
        "repository": {"id": repo_id, "full_name": "akarsh/sentinelreview"},
        "pull_request": {
            "number": number,
            "title": "Add search endpoint",
            "head": {"sha": "abc123"},
            "base": {"sha": "def456"},
            "user": {"login": "akarsh"},
        },
    }


def test_pull_request_webhook_errors_gracefully_when_repository_unknown(client):
    """No installation webhook has been received for this repo yet -- must not 500."""
    response = _post_webhook(client, "pull_request", _pr_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "error"
    assert "No known installation" in data["reason"]


def test_pull_request_webhook_ignores_non_triggering_action(client, db_session):
    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)

    response = _post_webhook(client, "pull_request", _pr_payload(action="closed"))
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert db_session.query(PullRequest).count() == 0


def test_pull_request_webhook_creates_pr_and_review_and_reports_auth_failure_when_unconfigured(
    client, db_session, fake_queue, monkeypatch
):
    """
    No GITHUB_APP_ID/GITHUB_PRIVATE_KEY configured (the default state for
    local dev without a registered App) -- the webhook must still succeed,
    persist the PR/Review rows, and report the auth failure clearly in the
    response rather than crashing or silently losing it.
    """
    from app.core.config import Settings
    monkeypatch.setattr("app.core.config.get_settings", lambda: Settings(_env_file=None))

    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)

    response = _post_webhook(client, "pull_request", _pr_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "queued"
    assert data["repo"] == "akarsh/sentinelreview"
    assert data["pr_number"] == 42
    assert data["auth_status"].startswith("auth_failed")
    assert "not configured" in data["auth_status"]

    pr = db_session.query(PullRequest).filter_by(number=42).one()
    assert pr.title == "Add search endpoint"
    review = db_session.query(Review).filter_by(pull_request_id=pr.id).one()

    # The review is enqueued for the real background job regardless of
    # whether the synchronous auth pre-check succeeded -- the job does its
    # own auth and will mark the review FAILED itself if that also fails
    # (see tests/test_review_worker.py), rather than the webhook silently
    # dropping the review instead of ever attempting it.
    assert data["job_id"] is not None
    assert len(fake_queue.enqueued) == 1
    _func, args, _kwargs = fake_queue.enqueued[0]
    assert args == (review.id,)
    assert review.triggered_sha == "abc123"


def test_pull_request_webhook_upserts_existing_pr_rather_than_duplicating(client, db_session):
    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)
    _post_webhook(client, "pull_request", _pr_payload(action="opened"))
    _post_webhook(client, "pull_request", _pr_payload(action="synchronize"))  # e.g. a new commit pushed

    assert db_session.query(PullRequest).filter_by(number=42).count() == 1
    # Each triggering event still gets its own Review row (a fresh scan per push).
    pr = db_session.query(PullRequest).filter_by(number=42).one()
    assert db_session.query(Review).filter_by(pull_request_id=pr.id).count() == 2


@respx.mock
def test_pull_request_webhook_acquires_real_installation_token_when_configured(client, db_session, monkeypatch):
    """The real end-to-end auth chain: JWT signed with a real keypair, exchanged via a mocked HTTP response."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_PRIVATE_KEY", private_pem)
    get_settings.cache_clear()

    respx.post("https://api.github.com/app/installations/9001/access_tokens").mock(
        return_value=httpx.Response(
            201, json={"token": "ghs_realchain_token", "expires_at": "2026-07-10T12:00:00Z"}
        )
    )

    _post_webhook(client, "installation", _INSTALLATION_PAYLOAD)
    response = _post_webhook(client, "pull_request", _pr_payload())

    assert response.status_code == 200
    data = response.json()
    assert data["auth_status"] == "installation_token_acquired"
    assert data["installation_token_expires_at"] == "2026-07-10T12:00:00Z"

    get_settings.cache_clear()
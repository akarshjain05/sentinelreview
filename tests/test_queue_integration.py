"""
The one test in this project that deliberately does NOT use a fake queue
or a fake worker: real Redis (redis-server running locally), a real RQ
Queue.enqueue() call, and a real RQ SimpleWorker popping and executing the
job synchronously in-process. This is the actual proof that "enqueue via
Redis/RQ" -- a literal TODO comment until this session -- really works
end-to-end, not just that the enqueue() call doesn't raise.

Requires a real Redis reachable at REDIS_URL (defaults to
redis://localhost:6379/0). If Redis isn't running, this test fails loudly
rather than silently skipping -- a skipped test here would quietly stop
proving the thing it exists to prove.
"""
import uuid

import httpx
import pytest
import respx
from app.core.config import get_settings
from app.db.models import (
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
from redis import Redis
from rq import Queue, SimpleWorker


@pytest.fixture
def real_redis_connection():
    settings = get_settings()
    conn = Redis.from_url(settings.redis_url)
    try:
        conn.ping()
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"This test requires a real Redis at {settings.redis_url} -- "
            f"start one with `redis-server --daemonize yes`. ({e})"
        )
    yield conn
    conn.flushdb()


@pytest.fixture
def db_session(monkeypatch, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # A real file-backed SQLite (not :memory:) -- the RQ worker in this
    # test runs the job function in the SAME process (SimpleWorker doesn't
    # fork), so an in-memory DB would actually be shared correctly here,
    # but using a real file matches how a genuinely separate worker
    # process (which cannot share another process's :memory: DB at all)
    # would have to work, and is a more honest test of the real deployment
    # shape.
    db_path = tmp_path / "queue_integration_test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    import app.jobs.review_worker as review_worker_module
    monkeypatch.setattr(review_worker_module, "SessionLocal", Session)

    session = Session()
    yield session
    session.close()


def _seed(db) -> str:
    inst = Installation(id=str(uuid.uuid4()), github_installation_id=9001, account_login="akarsh")
    db.add(inst)
    db.flush()
    repo = Repository(
        id=str(uuid.uuid4()), installation_id=inst.id, github_repo_id=5001, full_name="akarsh/sentinelreview",
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


@respx.mock
def test_real_redis_enqueue_and_real_worker_execution_end_to_end(real_redis_connection, db_session, monkeypatch):
    """
    The full real loop: enqueue a real RQ job onto a real Redis queue, then
    have a real RQ worker (not a mock, not a direct function call) pop and
    execute it, and confirm the review ends up COMPLETED with real
    findings in the real database -- exactly what a production worker
    process would do, just running synchronously in this test instead of
    as a separate long-lived process.
    """
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
        return_value=httpx.Response(201, json={"token": "ghs_test", "expires_at": "2026-08-01T00:00:00Z"})
    )
    respx.get("https://api.github.com/repos/akarsh/sentinelreview/pulls/42/files").mock(
        return_value=httpx.Response(200, json=[
            {
                "filename": "app/search.py",
                "status": "modified",
                "patch": '+cursor.execute("SELECT * FROM users WHERE name = " + name)\n',
            },
        ])
    )

    review_id = _seed(db_session)

    queue = Queue("sentinelreview-test-queue", connection=real_redis_connection)
    job = queue.enqueue(run_review_job, review_id)
    assert job.id is not None
    assert queue.count == 1  # really sitting in real Redis right now, unexecuted

    # A real worker, popping from the real queue -- SimpleWorker runs
    # in-process (no fork) so it can share this test's monkeypatched
    # SessionLocal and respx mocks, while still exercising RQ's real
    # dequeue/execute/result-store machinery, not a direct function call.
    worker = SimpleWorker([queue], connection=real_redis_connection)
    worker.work(burst=True)  # process everything currently queued, then return

    assert queue.count == 0  # the real queue is empty again -- it was actually consumed

    db_session.expire_all()
    review = db_session.get(Review, review_id)
    assert review.status == ReviewStatus.COMPLETED
    assert len(review.findings) >= 1
    assert any(f.cwe_id == "CWE-89" for f in review.findings)

    get_settings.cache_clear()
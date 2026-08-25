import os
os.environ["TESTING"] = "1"
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Route the app at test-collection time to a throwaway SQLite DB so tests
# never touch a real Postgres instance.
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_sentinelreview.db")


class _FakeJob:
    def __init__(self, id_: str):
        self.id = id_


class FakeQueue:
    """
    Records enqueue() calls instead of talking to a real Redis -- keeps
    most tests fast and isolated from infrastructure. Real end-to-end
    queue behavior (a real Redis, a real RQ worker actually popping and
    running the job) is covered separately in
    tests/test_queue_integration.py, which deliberately does NOT use this
    fake. Shared here (not duplicated per test file) since both
    test_webhooks.py and test_dashboard_api.py need it for anything that
    calls app.jobs.queue.get_review_queue.
    """
    def __init__(self):
        self.enqueued: list[tuple] = []

    def enqueue(self, func, *args, **kwargs):
        job = _FakeJob(id_=f"fake-job-{len(self.enqueued)}")
        self.enqueued.append((func, args, kwargs))
        return job


@pytest.fixture
def fake_queue():
    return FakeQueue()

@pytest.fixture(autouse=True)
def override_auth(monkeypatch):
    from app.auth.oauth import get_current_user
    from app.main import app
    
    # By default, mock the current user to return a test user with access to a fake installation
    def override_get_current_user():
        return {
            "login": "testuser",
            "id": 12345,
            "avatar_url": "https://example.com/avatar.png",
            "installations": [1, 9001, 999999], # We'll assume test repositories use these installation IDs
        }
        
    app.dependency_overrides[get_current_user] = override_get_current_user
    
    yield
    
    # Clean up after test
    app.dependency_overrides.pop(get_current_user, None)
from app.core.config import Settings

@pytest.fixture(autouse=True)
def _setup_test_env(monkeypatch):
    import os
    os.environ["TESTING"] = "1"
    
    # We clear the LRU cache so get_settings() re-evaluates
    from app.core.config import get_settings
    get_settings.cache_clear()





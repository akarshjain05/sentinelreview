"""
Redis/RQ queue connection. Kept as a single shared function (not a
module-level global) so tests can construct an isolated queue against a
fake/test Redis without import-time side effects, and so the connection is
read from current settings rather than whatever REDIS_URL existed at
import time.

get_review_queue is used the same way app.db.session.get_db is: as a
FastAPI dependency, overridable in tests via app.dependency_overrides so
most webhook tests don't need a real Redis running -- only the dedicated
queue integration test does.
"""
from __future__ import annotations  # noqa: I001

from redis import Redis
from rq import Queue

from app.core.config import get_settings

_QUEUE_NAME = "sentinelreview-reviews"


def get_review_queue() -> Queue:
    settings = get_settings()
    connection = Redis.from_url(settings.redis_url)
    return Queue(_QUEUE_NAME, connection=connection)
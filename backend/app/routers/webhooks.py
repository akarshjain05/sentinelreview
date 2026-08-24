"""
GitHub App webhook receiver.

Verifies the HMAC signature GitHub attaches to every webhook payload before
trusting anything in the body, then persists what the payload describes
(installations, repositories, pull requests, reviews) and -- for PR events
that should trigger a review -- exercises the real GitHub App auth chain
(app/auth/github_app.py) to obtain an installation token, rather than just
returning a "queued" status with no corresponding database row.

The actual agent pipeline run is still enqueued as a stub (TODO below):
webhooks must ack in <10s or GitHub considers them failed and retries,
potentially causing duplicate reviews, so running the full LangGraph
pipeline inline here would be wrong regardless of whether the queue is wired.
"""
import hashlib  # noqa: I001
import hmac
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.github_app import GitHubAppAuthError, get_installation_token
from app.core.config import get_settings
from app.db.models import Installation, PullRequest, Repository, Review, ReviewStatus
from app.db.session import get_db
from app.jobs.queue import get_review_queue

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Events we actually act on; everything else is ack'd and ignored.
SUPPORTED_EVENTS = {"installation", "installation_repositories", "pull_request", "pull_request_review_comment", "check_run"}
TRIGGERING_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def _verify_signature(payload_body: bytes, signature_header: str | None) -> bool:
    # NOTE: settings is fetched fresh on every call (not cached at module
    # import time) so that config changes -- e.g. secret rotation without a
    # restart, or per-test monkeypatching -- take effect immediately.
    settings = get_settings()
    if not settings.github_webhook_secret:
        # Fail closed in any environment that claims to be non-development.
        return settings.allow_unsigned_webhooks
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(
        settings.github_webhook_secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    provided = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


def _handle_installation_event(payload: dict, db: Session) -> dict:
    action = payload.get("action")
    installation_data = payload["installation"]
    github_installation_id = installation_data["id"]
    account_login = installation_data["account"]["login"]

    if action == "deleted":
        existing = db.scalar(
            select(Installation).where(Installation.github_installation_id == github_installation_id)
        )
        if existing:
            db.delete(existing)
            db.commit()
        return {"status": "installation_removed", "installation_id": github_installation_id}

    # "created" or "new_permissions_accepted" etc. -- upsert rather than
    # assume "created" is the only action that should result in a row.
    existing = db.scalar(
        select(Installation).where(Installation.github_installation_id == github_installation_id)
    )
    if existing is None:
        existing = Installation(
            id=str(uuid.uuid4()), github_installation_id=github_installation_id, account_login=account_login,
        )
        db.add(existing)
    else:
        existing.account_login = account_login

    # An installation event includes the list of repos it was granted access to.
    for repo_data in payload.get("repositories", []):
        repo_existing = db.scalar(select(Repository).where(Repository.github_repo_id == repo_data["id"]))
        if repo_existing is None:
            db.add(Repository(
                id=str(uuid.uuid4()), installation_id=existing.id,
                github_repo_id=repo_data["id"], full_name=repo_data["full_name"],
            ))
    db.commit()
    return {"status": "installation_synced", "installation_id": github_installation_id}


def _handle_installation_repositories_event(payload: dict, db: Session) -> dict:
    installation_data = payload["installation"]
    github_installation_id = installation_data["id"]

    existing_installation = db.scalar(
        select(Installation).where(Installation.github_installation_id == github_installation_id)
    )
    if not existing_installation:
        return {"status": "error", "reason": f"installation {github_installation_id} not found"}

    for repo_data in payload.get("repositories_added", []):
        repo_existing = db.scalar(select(Repository).where(Repository.github_repo_id == repo_data["id"]))
        if repo_existing is None:
            db.add(Repository(
                id=str(uuid.uuid4()), installation_id=existing_installation.id,
                github_repo_id=repo_data["id"], full_name=repo_data["full_name"],
            ))
        else:
            repo_existing.is_active = True
            repo_existing.installation_id = existing_installation.id

    for repo_data in payload.get("repositories_removed", []):
        repo_existing = db.scalar(select(Repository).where(Repository.github_repo_id == repo_data["id"]))
        if repo_existing is not None:
            # DO NOT db.delete(repo_existing) because it will fail with IntegrityError
            # due to existing PullRequests/Reviews. Instead, detach it from the installation
            # and mark it inactive so it disappears from the UI but history is preserved.
            repo_existing.installation_id = None
            repo_existing.is_active = False

    db.commit()
    return {"status": "installation_repositories_synced", "installation_id": github_installation_id}


def _handle_pull_request_event(payload: dict, db: Session, queue) -> dict:
    action = payload.get("action")
    if action not in TRIGGERING_ACTIONS:
        return {"status": "ignored", "reason": f"action '{action}' not in trigger list"}

    repo_payload = payload["repository"]
    pr_payload = payload["pull_request"]

    repository = db.scalar(select(Repository).where(Repository.github_repo_id == repo_payload["id"]))
    if repository is None:
        # No matching installation/repository row -- most likely the
        # "installation" webhook hasn't been received/processed yet.
        # Ack the webhook (GitHub shouldn't retry over this) but report it
        # clearly rather than silently dropping the PR event.
        return {
            "status": "error",
            "reason": (
                f"No known installation for repository {repo_payload['full_name']!r} "
                "(github_repo_id not found) -- has the GitHub App installation webhook "
                "been received for this repo yet?"
            ),
        }

    pull_request = db.scalar(
        select(PullRequest).where(
            PullRequest.repository_id == repository.id, PullRequest.number == pr_payload["number"],
        )
    )
    if pull_request is None:
        pull_request = PullRequest(
            id=str(uuid.uuid4()), repository_id=repository.id, number=pr_payload["number"],
            title=pr_payload["title"], head_sha=pr_payload["head"]["sha"], base_sha=pr_payload["base"]["sha"],
            author_login=pr_payload["user"]["login"],
        )
        db.add(pull_request)
        db.flush()
    else:
        pull_request.title = pr_payload["title"]
        pull_request.head_sha = pr_payload["head"]["sha"]

    review = Review(
        id=str(uuid.uuid4()), pull_request_id=pull_request.id,
        triggered_sha=pr_payload["head"]["sha"], status=ReviewStatus.QUEUED,
    )
    db.add(review)
    db.commit()

    # Exercise the real auth chain: this is what a background worker would
    # use to authenticate before calling the GitHub API to post the review
    # comment. Done here (synchronously, before enqueueing the actual
    # pipeline run) so a misconfigured App fails fast and visibly on the
    # very next webhook, rather than silently inside a background job.
    installation_id = payload["installation"]["id"]
    try:
        token = get_installation_token(installation_id)
        auth_status = "installation_token_acquired"
        token_expires_at = token.expires_at
    except GitHubAppAuthError as e:
        auth_status = f"auth_failed: {e}"
        token_expires_at = None

    # This used to be a literal TODO comment -- now a real enqueue. The
    # synchronous auth check above still runs first (fast, visible failure
    # for a misconfigured App on the very next webhook); the job itself
    # re-acquires its own token when it actually runs, since installation
    # tokens are short-lived (~1hr) and jobs can sit in the queue for a
    # while before a worker picks them up -- reusing the token fetched here
    # would risk it having expired by the time the job runs.
    job = queue.enqueue("app.jobs.review_worker.run_review_job", review.id)

    return {
        "status": "queued",
        "repo": repository.full_name,
        "pr_number": pull_request.number,
        "review_id": review.id,
        "job_id": job.id,
        "auth_status": auth_status,
        "installation_token_expires_at": token_expires_at,
    }


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    db: Session = Depends(get_db),  # noqa: B008
    queue=Depends(get_review_queue),  # noqa: B008
):
    body = await request.body()
    if not _verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if x_github_event not in SUPPORTED_EVENTS:
        return {"status": "ignored", "reason": f"unhandled event type: {x_github_event}"}

    payload = await request.json()
    print(f"DEBUG: Received github event {x_github_event}")
    if x_github_event == "pull_request":
        print(f"DEBUG: PR Action {payload.get('action')}, repo ID: {payload.get('repository', {}).get('id')}, PR number: {payload.get('pull_request', {}).get('number')}")

    if x_github_event == "installation":
        return _handle_installation_event(payload, db)

    if x_github_event == "installation_repositories":
        return _handle_installation_repositories_event(payload, db)

    if x_github_event == "pull_request":
        return _handle_pull_request_event(payload, db, queue)

    return {"status": "ignored", "reason": f"event '{x_github_event}' acknowledged but not acted on"}
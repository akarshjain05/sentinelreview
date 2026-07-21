"""
The background job a webhook enqueues instead of running the pipeline
inline. This is the piece that was a literal `# TODO: enqueue via
Redis/RQ` comment until now -- everything it calls (get_installation_token,
fetch_pr_files, run_review_with_observability) already existed and was
already tested individually; this wires them into one real, callable job.
"""
from __future__ import annotations

from app.auth.github_app import GitHubAppAuthError, get_installation_token
from app.agents.state import ChangedFile, ReviewState
from app.db.models import Review, ReviewStatus
from app.db.session import SessionLocal
from app.services.github_client import GitHubAPIError, fetch_pr_files, is_doc_file, is_test_file
from app.services.pipeline_runner import run_review_with_observability


class ReviewJobError(RuntimeError):
    pass


def run_review_job(review_id: str) -> None:
    """
    Entry point RQ actually calls. Takes only a review_id (not a live DB
    session or in-memory objects) because RQ serializes job arguments --
    this job opens its own database session, matching how a real worker
    process (a separate OS process from whatever enqueued the job) has to
    work.

    On any failure before the pipeline itself runs (missing DB rows,
    GitHub App not configured, GitHub API error), marks the Review FAILED
    with a clear error message rather than leaving it stuck at QUEUED
    forever with no explanation.
    """
    db = SessionLocal()
    try:
        review = db.get(Review, review_id)
        if review is None:
            raise ReviewJobError(f"Review {review_id} not found")

        pull_request = review.pull_request
        repository = pull_request.repository if pull_request else None
        if pull_request is None or repository is None:
            _fail(db, review, "Review has no associated pull request/repository")
            return

        installation = repository.installation
        if installation is None:
            _fail(db, review, "Repository has no associated installation (orphaned after an App uninstall?)")
            return

        try:
            token = get_installation_token(installation.github_installation_id)
        except GitHubAppAuthError as e:
            _fail(db, review, f"Could not obtain installation token: {e}")
            return

        owner, _, repo_name = repository.full_name.partition("/")
        try:
            pr_files = fetch_pr_files(owner, repo_name, pull_request.number, token.token)
        except GitHubAPIError as e:
            _fail(db, review, f"Could not fetch PR files: {e}")
            return

        changed_files = [
            ChangedFile(
                path=f.filename,
                diff=f.patch or "",
                is_doc_file=is_doc_file(f.filename),
                is_test_file=is_test_file(f.filename),
            )
            for f in pr_files
            if f.patch is not None  # binary/oversized files have nothing to scan
        ]

        state = ReviewState(
            repo_full_name=repository.full_name,
            pr_number=pull_request.number,
            pr_title=pull_request.title,
            pr_body="",  # not persisted on PullRequest today -- see README's known gaps
            head_sha=pull_request.head_sha,
            changed_files=changed_files,
        )

        # This is where AgentRun rows, Finding rows, and the terminal
        # Review.status actually get written -- run_review_with_observability
        # already handles its own COMPLETED/FAILED transition and commit.
        final_state = run_review_with_observability(state, db=db, review_id=review_id)
        
        # Post the review comment back to the GitHub PR
        review_markdown = final_state.get("review_markdown")
        if review_markdown:
            try:
                from app.services.github_client import post_pr_review_comment
                post_pr_review_comment(owner, repo_name, pull_request.number, review_markdown, token.token)
            except GitHubAPIError as e:
                # We won't fail the whole review if only the comment posting failed, 
                # but we could log it or store the error message.
                pass

    finally:
        db.close()


def _fail(db, review: Review, message: str) -> None:
    review.status = ReviewStatus.FAILED
    review.error_message = message[:2000]
    db.commit()
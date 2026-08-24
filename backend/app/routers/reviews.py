import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.db.models import KnowledgeDocument, PullRequest, Review, ReviewStatus, Repository, Installation
from app.db.session import get_db
from app.jobs.queue import get_review_queue
from app.jobs.review_worker import run_review_job
from app.auth.oauth import get_current_user

router = APIRouter(prefix="/reviews", tags=["reviews"])


def _severity_counts(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if key in counts:
            counts[key] += 1
    return counts


def _resolve_citations(db: Session, cited_document_ids: str | None) -> list[dict]:
    """
    Resolves a Finding's comma-separated cited_document_ids (e.g. "CWE-89")
    into the actual KnowledgeDocument rows they reference -- title, source,
    url -- rather than making the frontend deal with bare ID strings it
    can't do anything with. Real citation data, from the actual retrieval
    step (app/agents/graph.py's retrieval_node), not fabricated per-finding.
    """
    if not cited_document_ids:
        return []
    ids = [i.strip() for i in cited_document_ids.split(",") if i.strip()]
    if not ids:
        return []

    docs = db.query(KnowledgeDocument).filter(KnowledgeDocument.external_id.in_(ids)).all()
    return [
        {"external_id": d.external_id, "title": d.title, "source": d.source, "url": d.url}
        for d in docs
    ]


@router.get("")
def list_reviews(
    repo: str | None = None,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Reviews newest-first, with enough summary data for a list view without N+1 detail fetches."""
    installations = user.get("installations", [])
    
    query = (
        db.query(Review)
        .join(Review.pull_request)
        .join(PullRequest.repository)
        .join(Repository.installation)
        .filter(Installation.github_installation_id.in_(installations))
        .options(joinedload(Review.pull_request).joinedload(PullRequest.repository))
    )
    
    if repo:
        query = query.filter(Repository.full_name == repo)
        
    reviews = query.order_by(Review.started_at.desc().nullslast()).all()
    out = []
    for review in reviews:
        pr = review.pull_request
        repo = pr.repository if pr else None
        out.append({
            "id": review.id,
            "status": review.status,
            "repo_full_name": repo.full_name if repo else None,
            "pr_number": pr.number if pr else None,
            "pr_title": pr.title if pr else None,
            "started_at": review.started_at,
            "completed_at": review.completed_at,
            "error_message": review.error_message,
            "total_latency_ms": review.total_latency_ms,
            "finding_count": len(review.findings),
            "severity_counts": _severity_counts(review.findings),
        })
    return out


@router.get("/{review_id}")
def get_review(
    review_id: str, 
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> dict:
    review = db.get(Review, review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")

    pr = review.pull_request
    repo = pr.repository if pr else None
    
    # Authorization check
    installations = user.get("installations", [])
    if not repo or not repo.installation or repo.installation.github_installation_id not in installations:
        raise HTTPException(status_code=403, detail="Not authorized to view this review")

    return {
        "id": review.id,
        "status": review.status,
        "repo_full_name": repo.full_name if repo else None,
        "pr_number": pr.number if pr else None,
        "pr_title": pr.title if pr else None,
        "started_at": review.started_at,
        "completed_at": review.completed_at,
            "error_message": review.error_message,
        "total_cost_usd": review.total_cost_usd,
        "total_latency_ms": review.total_latency_ms,
        "finding_count": len(review.findings),
        "severity_counts": _severity_counts(review.findings),
        "findings": [
            {
                "id": f.id,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "cwe_id": f.cwe_id,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "source": f.source,
                "explanation": f.explanation,
                "code_snippet": f.code_snippet,
                "citations": _resolve_citations(db, f.cited_document_ids),
                "patch_suggestions": [
                    {
                        "id": p.id,
                        "diff": p.diff,
                        "reasoning": p.reasoning,
                        "citations": _resolve_citations(db, p.cited_document_ids),
                        "verification_runs": [
                            {
                                "id": v.id,
                                "issue_resolved": v.issue_resolved,
                                "tests_passed": v.tests_passed,
                                "build_succeeded": v.build_succeeded,
                                "introduced_new_findings": v.introduced_new_findings,
                                "sandbox_log": v.sandbox_log,
                                "created_at": v.created_at,
                            }
                            for v in p.verification_runs
                        ]
                    }
                    for p in f.patch_suggestions
                ]
            }
            for f in review.findings
        ],
    }


@router.get("/{review_id}/findings/{finding_id}/patch")
def get_finding_patch(
    review_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> dict:
    review = db.get(Review, review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")

    pr = review.pull_request
    repo = pr.repository if pr else None
    
    # Authorization check
    installations = user.get("installations", [])
    if not repo or not repo.installation or repo.installation.github_installation_id not in installations:
        raise HTTPException(status_code=403, detail="Not authorized to view this review")

    finding = next((f for f in review.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "patch_suggestions": [
            {
                "id": p.id,
                "diff": p.diff,
                "reasoning": p.reasoning,
                "citations": _resolve_citations(db, p.cited_document_ids),
                "verification_runs": [
                    {
                        "id": v.id,
                        "issue_resolved": v.issue_resolved,
                        "tests_passed": v.tests_passed,
                        "build_succeeded": v.build_succeeded,
                        "introduced_new_findings": v.introduced_new_findings,
                        "sandbox_log": v.sandbox_log,
                        "created_at": v.created_at,
                    }
                    for v in p.verification_runs
                ]
            }
            for p in finding.patch_suggestions
        ]
    }


@router.post("/{review_id}/rerun")
def rerun_review(
    review_id: str, 
    db: Session = Depends(get_db), 
    queue=Depends(get_review_queue),
    user: dict = Depends(get_current_user),
) -> dict:
    """
    Creates a fresh Review row for the same pull request and enqueues it --
    matching how a new push creates a new Review rather than resetting an
    old one (see app/routers/webhooks.py's _handle_pull_request_event),
    so a review's history (its original findings, timing, status) stays
    intact even after a rerun instead of being overwritten in place.
    """
    original = db.get(Review, review_id)
    if original is None:
        raise HTTPException(status_code=404, detail="Review not found")

    pr = original.pull_request
    repo = pr.repository if pr else None
    installations = user.get("installations", [])
    if not repo or not repo.installation or repo.installation.github_installation_id not in installations:
        raise HTTPException(status_code=403, detail="Not authorized to rerun this review")

    new_review = Review(
        id=str(uuid.uuid4()),
        pull_request_id=original.pull_request_id,
        triggered_sha=original.triggered_sha,
        status=ReviewStatus.QUEUED,
        is_manual_rerun=True,
    )
    db.add(new_review)
    db.commit()

    job = queue.enqueue("app.jobs.review_worker.run_review_job", new_review.id)

    return {"status": "requeued", "review_id": new_review.id, "job_id": job.id}
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth.oauth import get_current_user
from app.db.models import (
    Installation,
    KnowledgeDocument,
    PullRequest,
    Repository,
    Review,
    ReviewStatus,
)
from app.db.session import get_db
from app.jobs.queue import get_review_queue

router = APIRouter(prefix="/reviews", tags=["reviews"])


def _severity_counts(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if key in counts:
            counts[key] += 1
    return counts


def _resolve_all_citations(db: Session, all_id_strings: list[str | None]) -> dict[str, dict]:
    """Batch resolves multiple comma-separated citation strings into a single lookup dict."""
    ids_to_fetch = set()
    for id_str in all_id_strings:
        if id_str:
            for i in id_str.split(","):
                if i.strip():
                    ids_to_fetch.add(i.strip())
    
    if not ids_to_fetch:
        return {}
        
    docs = db.query(KnowledgeDocument).filter(KnowledgeDocument.external_id.in_(list(ids_to_fetch))).all()
    return {
        d.external_id: {"external_id": d.external_id, "title": d.title, "source": d.source, "url": d.url}
        for d in docs
    }


def _map_citations(id_str: str | None, lookup: dict[str, dict]) -> list[dict]:
    """Maps a comma-separated citation string using a pre-fetched lookup dict."""
    if not id_str:
        return []
    ids = [i.strip() for i in id_str.split(",") if i.strip()]
    return [lookup[i] for i in ids if i in lookup]


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
        .options(
            joinedload(Review.pull_request).joinedload(PullRequest.repository),
            selectinload(Review.findings)
        )
    )
    
    if repo:
        query = query.filter(Repository.full_name == repo)
        
    reviews = query.order_by(Review.started_at.desc().nullslast()).all()
    out = []
    for review in reviews:
        pr = review.pull_request
        repo = pr.repository if pr else None  # type: ignore
        out.append({
            "id": review.id,
            "status": review.status,
            "repo_full_name": repo.full_name if repo else None,  # type: ignore
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

    # Collect all citation IDs upfront to avoid N+1 queries
    all_citation_strings = []
    for f in review.findings:
        all_citation_strings.append(f.cited_document_ids)
        for p in f.patch_suggestions:
            all_citation_strings.append(p.cited_document_ids)
            
    citations_lookup = _resolve_all_citations(db, all_citation_strings)

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
                "citations": _map_citations(f.cited_document_ids, citations_lookup),
                "patch_suggestions": [
                    {
                        "id": p.id,
                        "diff": p.diff,
                        "reasoning": p.reasoning,
                        "citations": _map_citations(p.cited_document_ids, citations_lookup),
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

    # Collect citation IDs for this finding's patches
    all_citation_strings = [p.cited_document_ids for p in finding.patch_suggestions]
    citations_lookup = _resolve_all_citations(db, all_citation_strings)

    return {
        "patch_suggestions": [
            {
                "id": p.id,
                "diff": p.diff,
                "reasoning": p.reasoning,
                "citations": _map_citations(p.cited_document_ids, citations_lookup),
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

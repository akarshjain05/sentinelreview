from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import Installation, Repository, Review, PullRequest
from app.db.session import get_db
from app.auth.oauth import get_current_user

router = APIRouter(prefix="/repositories", tags=["repositories"])

@router.get("")
def list_repositories(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List all repositories the user has access to, with their review counts."""
    installations = user.get("installations", [])
    
    query = (
        db.query(
            Repository,
            func.count(Review.id).label("review_count")
        )
        .join(Installation, Installation.id == Repository.installation_id)
        .outerjoin(PullRequest, PullRequest.repository_id == Repository.id)
        .outerjoin(Review, Review.pull_request_id == PullRequest.id)
        .filter(Installation.github_installation_id.in_(installations))
        .group_by(Repository.id)
        .order_by(Repository.full_name)
    )
    
    results = query.all()
    
    out = []
    for repo, review_count in results:
        out.append({
            "id": repo.id,
            "full_name": repo.full_name,
            "default_branch": repo.default_branch,
            "is_active": repo.is_active,
            "created_at": repo.created_at,
            "review_count": review_count,
        })
        
    return out

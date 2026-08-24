"""
Aggregates real AgentRun data (per-node latency/success/cost from every
pipeline run -- see app/services/pipeline_runner.py) into the numbers a
"Latency Dashboard" actually needs: average/min/max latency per pipeline
stage, success rate, and review-level totals.

This data has existed since the observability work (AgentRun rows are
written on every real pipeline run) but was previously invisible -- no
endpoint ever exposed it. This is that endpoint.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.oauth import get_current_user
from app.db.models import AgentRun, Review, Finding, Repository, Installation, PullRequest
from app.db.session import get_db
from app.services.pipeline_runner import _NODE_TO_AGENT_NAME

router = APIRouter(prefix="/observability", tags=["observability"])

# Real pipeline execution order (Triage -> Static Analysis -> Retrieval ->
# Classification -> Fix Suggestion -> Verification -> Reporting), reused
# from pipeline_runner.py's own node-to-agent mapping rather than defined
# a second time here -- two independent orderings of the same 7 stages
# would drift the moment either one changes.
_PIPELINE_ORDER = [agent.value for agent in _NODE_TO_AGENT_NAME.values()]


@router.get("/latency")
def get_latency_stats(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> dict:
    installation_ids = user.get("installations", [])
    if not installation_ids:
        return {
            "per_agent": [],
            "total_reviews": 0,
            "avg_review_latency_ms": None,
            "total_cost_usd": 0.0,
        }

    per_agent = (
        db.query(
            AgentRun.agent_name,
            func.count(AgentRun.id).label("run_count"),
            func.avg(AgentRun.latency_ms).label("avg_latency_ms"),
            func.min(AgentRun.latency_ms).label("min_latency_ms"),
            func.max(AgentRun.latency_ms).label("max_latency_ms"),
        )
        .join(Review, AgentRun.review_id == Review.id)
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .group_by(AgentRun.agent_name)
        .all()
    )

    per_agent_stats = []
    for agent_name, run_count, avg_latency, min_latency, max_latency in per_agent:
        succeeded_count = (
            db.query(func.count(AgentRun.id))
            .join(Review, AgentRun.review_id == Review.id)
            .join(PullRequest, Review.pull_request_id == PullRequest.id)
            .join(Repository, PullRequest.repository_id == Repository.id)
            .join(Installation, Repository.installation_id == Installation.id)
            .filter(Installation.github_installation_id.in_(installation_ids))
            .filter(AgentRun.agent_name == agent_name, AgentRun.succeeded.is_(True))
            .scalar()
        )
        per_agent_stats.append({
            "agent_name": agent_name,
            "run_count": run_count,
            "avg_latency_ms": round(avg_latency, 1) if avg_latency is not None else None,
            "min_latency_ms": min_latency,
            "max_latency_ms": max_latency,
            "success_rate": round(succeeded_count / run_count, 3) if run_count else None,
        })

    total_reviews = (
        db.query(func.count(Review.id))
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .scalar()
    )
    avg_review_latency = (
        db.query(func.avg(Review.total_latency_ms))
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .filter(Review.total_latency_ms > 0)
        .scalar()
    )
    total_cost = (
        db.query(func.sum(AgentRun.cost_usd))
        .join(Review, AgentRun.review_id == Review.id)
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .scalar() or 0.0
    )

    return {
        "per_agent": sorted(per_agent_stats, key=lambda a: _PIPELINE_ORDER.index(a["agent_name"])),
        "total_reviews": total_reviews,
        "avg_review_latency_ms": round(avg_review_latency, 1) if avg_review_latency is not None else None,
        "total_cost_usd": total_cost,
        # Honest, not hidden: cost_usd is written to every AgentRun row but
        # nothing in this pipeline currently calls a metered LLM API and
        # sets it to a real value (the classifier/generator clients are
        # mocked -- see README's "HF classifier finding"), so this is
        # always 0.0 right now, not a real measurement of $0 spend.
    }

@router.get("/dashboard")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> dict:
    installation_ids = user.get("installations", [])
    if not installation_ids:
        return {"findings_by_severity": [], "findings_over_time": [], "reviews_over_time": []}

    # 1. findings_by_severity
    severity_query = (
        db.query(Finding.severity, func.count(Finding.id).label("count"))
        .join(Review, Finding.review_id == Review.id)
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .group_by(Finding.severity)
        .all()
    )
    findings_by_severity = [
        {"severity": sev.value if hasattr(sev, "value") else sev, "count": count}
        for sev, count in severity_query
    ]

    # 2. findings_over_time
    # Use SQLite/Postgres compatible date truncation
    time_query = (
        db.query(func.date(Review.completed_at).label("date"), func.count(Finding.id).label("count"))
        .join(Review, Finding.review_id == Review.id)
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .filter(Review.completed_at.isnot(None))
        .group_by(func.date(Review.completed_at))
        .all()
    )
    findings_over_time = [
        {"date": date_str, "count": count}
        for date_str, count in time_query
        if date_str
    ]

    # 3. reviews_over_time
    reviews_query = (
        db.query(
            func.date(Review.completed_at).label("date"),
            func.avg(Review.total_latency_ms).label("avg_latency_ms"),
            func.sum(Review.total_cost_usd).label("total_cost_usd"),
            func.count(Review.id).label("review_count")
        )
        .join(PullRequest, Review.pull_request_id == PullRequest.id)
        .join(Repository, PullRequest.repository_id == Repository.id)
        .join(Installation, Repository.installation_id == Installation.id)
        .filter(Installation.github_installation_id.in_(installation_ids))
        .filter(Review.completed_at.isnot(None))
        .group_by(func.date(Review.completed_at))
        .all()
    )
    reviews_over_time = [
        {
            "date": date_str,
            "avg_latency_ms": round(avg_lat, 1) if avg_lat else 0,
            "total_cost_usd": round(tot_cost, 4) if tot_cost else 0,
            "review_count": count
        }
        for date_str, avg_lat, tot_cost, count in reviews_query
        if date_str
    ]

    return {
        "findings_by_severity": findings_by_severity,
        "findings_over_time": findings_over_time,
        "reviews_over_time": reviews_over_time
    }
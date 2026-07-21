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
from app.db.models import AgentRun, Review
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
    per_agent = (
        db.query(
            AgentRun.agent_name,
            func.count(AgentRun.id).label("run_count"),
            func.avg(AgentRun.latency_ms).label("avg_latency_ms"),
            func.min(AgentRun.latency_ms).label("min_latency_ms"),
            func.max(AgentRun.latency_ms).label("max_latency_ms"),
        )
        .group_by(AgentRun.agent_name)
        .all()
    )

    # succeeded_count is computed via a separate per-agent query below
    # rather than summed in the query above: summing a boolean column
    # directly (e.g. func.sum(AgentRun.succeeded)) is portable in Postgres
    # but not reliably so in SQLite, and this project runs against both
    # (see docker-compose.yml vs. the SQLite dev path) -- a plain COUNT
    # with a WHERE filter is the version that's actually correct on both.
    per_agent_stats = []
    for agent_name, run_count, avg_latency, min_latency, max_latency in per_agent:
        succeeded_count = (
            db.query(func.count(AgentRun.id))
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

    total_reviews = db.query(func.count(Review.id)).scalar()
    avg_review_latency = db.query(func.avg(Review.total_latency_ms)).filter(Review.total_latency_ms > 0).scalar()
    total_cost = db.query(func.sum(AgentRun.cost_usd)).scalar() or 0.0

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
        "cost_tracking_note": (
            "cost_usd is not yet populated by any real LLM call in this pipeline "
            "(classification/generation clients are currently mocked) -- this "
            "total reflects that, not a genuine $0 cost."
        ),
    }
"""
Wraps the compiled LangGraph pipeline to record a real AgentRun row per node
execution -- this is the observability backend the README lists as
"AgentRun table exists to receive this data once wired." It's now wired.

Rather than a remote tracing service (Langfuse/Phoenix aren't reachable
from this environment), this writes directly to the same Postgres/SQLite
database as everything else, using LangGraph's `stream()` API to observe
each node transition. That's a legitimate, real observability backend for
a solo project's first version -- Langfuse remains a documented upgrade for
when you want cross-review dashboards.
"""
from __future__ import annotations  # noqa: I001

import time
import uuid

from sqlalchemy.orm import Session

from app.agents.graph import build_graph
from app.agents.state import ReviewState
from app.db.models import AgentName, AgentRun, Finding, Review, ReviewStatus, Severity

_NODE_TO_AGENT_NAME = {
    "triage": AgentName.TRIAGE,
    "static_analysis": AgentName.STATIC_ANALYSIS,
    "retrieval": AgentName.RETRIEVAL,
    "classification": AgentName.CLASSIFICATION,
    "fix_suggestion": AgentName.FIX_SUGGESTION,
    "verification": AgentName.VERIFICATION,
    "reporting": AgentName.REPORTING,
}


def run_review_with_observability(
    state: ReviewState,
    *,
    db: Session,
    review_id: str,
    graph=None,
) -> dict:
    """
    Executes the pipeline node-by-node via graph.stream(), writing one
    AgentRun row per node with real wall-clock latency, and updates the
    parent Review row's status/timing/aggregate latency as it goes.

    Returns the final merged state dict, same shape as graph.invoke() would.
    """
    graph = graph or build_graph()

    review = db.get(Review, review_id)
    if review is None:
        raise ValueError(f"Review {review_id} not found")

    review.status = ReviewStatus.RUNNING
    from datetime import datetime, timezone
    review.started_at = datetime.now(timezone.utc)
    db.commit()

    final_state: dict = {}
    total_latency_ms = 0
    total_cost_usd = 0.0

    try:
        start = time.perf_counter()
        for step_output in graph.stream(state):
            latency_ms = int((time.perf_counter() - start) * 1000)
            
            # step_output looks like {"<node_name>": {<partial state update>}}
            for node_name, partial_update in step_output.items():
                agent_name = _NODE_TO_AGENT_NAME.get(node_name)
                if agent_name is None:
                    continue  # unknown/internal node, skip rather than fail the whole review

                run = AgentRun(
                    id=str(uuid.uuid4()),
                    review_id=review_id,
                    agent_name=agent_name,
                    attempt=1,
                    output_summary=_summarize_update(node_name, partial_update),
                    latency_ms=latency_ms,
                    succeeded=True,
                    tokens_used=partial_update.get("tokens_used", 0),
                    cost_usd=partial_update.get("cost_usd", 0.0),
                )
                db.add(run)
                total_latency_ms += latency_ms
                total_cost_usd += partial_update.get("cost_usd", 0.0)
                final_state.update(partial_update)
            
            start = time.perf_counter()
        db.commit()

        # This was a real, previously-hidden gap: findings only ever lived
        # in final_state (in-memory), never written to the `findings`
        # table -- meaning every review that went through this function
        # for real would show zero findings in the dashboard regardless of
        # what the pipeline actually detected. Caught by
        # tests/test_review_worker.py's end-to-end test asserting on
        # review.findings after a real run, not by any earlier test (they
        # all checked either the graph's return value directly or
        # AgentRun rows, never Finding persistence).
        
        # We also need to map finding dicts to their DB models to attach patch suggestions
        from app.db.models import PatchSuggestion, VerificationRun
        
        # Track finding models by index since PatchSuggestion references finding_index
        finding_models = []
        for finding in final_state.get("findings", []):
            db_finding = Finding(
                id=str(uuid.uuid4()),
                review_id=review_id,
                file_path=finding.file_path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                cwe_id=finding.cwe_id,
                vulnerability_type=finding.vulnerability_type,
                severity=Severity(finding.severity),
                confidence=finding.confidence,
                source=finding.source,
                explanation=finding.explanation,
                code_snippet=finding.code_snippet,
                cited_document_ids=",".join(finding.cited_document_ids) if getattr(finding, 'cited_document_ids', None) else None,
            )
            db.add(db_finding)
            finding_models.append(db_finding)
        
        db.flush() # Flush to ensure finding IDs are available for PatchSuggestions
        
        # Persist Patch Suggestions
        patch_models = []
        for patch in final_state.get("patch_suggestions", []):
            db_finding = finding_models[patch.finding_index] if 0 <= patch.finding_index < len(finding_models) else None  # type: ignore
            db_patch = None
            if db_finding:
                db_patch = PatchSuggestion(
                    id=str(uuid.uuid4()),
                    finding_id=db_finding.id,
                    diff=patch.diff,
                    reasoning=patch.reasoning,
                    cited_document_ids=",".join(patch.cited_document_ids) if getattr(patch, 'cited_document_ids', None) else None,
                )
                db.add(db_patch)
            patch_models.append(db_patch)

        db.flush()
        
        # Persist Verification Runs
        for verification in final_state.get("verification_outcomes", []):
            db_patch = patch_models[verification.patch_index] if 0 <= verification.patch_index < len(patch_models) else None
            if db_patch:
                db_verification = VerificationRun(
                    id=str(uuid.uuid4()),
                    patch_suggestion_id=db_patch.id,
                    issue_resolved=verification.issue_resolved,
                    tests_passed=verification.tests_passed,
                    build_succeeded=verification.build_succeeded,
                    introduced_new_findings=verification.introduced_new_findings,
                    sandbox_log=verification.log,
                )
                db.add(db_verification)

        db.commit()

        review.status = ReviewStatus.COMPLETED
        review.completed_at = datetime.now(timezone.utc)
        review.total_latency_ms = total_latency_ms
        review.total_cost_usd = total_cost_usd
        db.commit()

    except Exception as e:
        review.status = ReviewStatus.FAILED
        review.completed_at = datetime.now(timezone.utc)
        review.error_message = str(e)[:2000]
        db.commit()
        raise

    return final_state


def _summarize_update(node_name: str, update: dict) -> str:
    """Small, storable summary of what a node produced -- not the full payload (keep AgentRun rows lightweight)."""
    if node_name == "static_analysis":
        return f"{len(update.get('raw_analyzer_findings', []))} raw finding(s)"
    if node_name == "retrieval":
        return f"{len(update.get('retrieved_knowledge', []))} knowledge snippet(s) retrieved"
    if node_name == "classification":
        return f"{len(update.get('findings', []))} finding(s) classified"
    if node_name == "fix_suggestion":
        return f"{len(update.get('patch_suggestions', []))} patch suggestion(s)"
    if node_name == "verification":
        return f"{len(update.get('verification_outcomes', []))} verification outcome(s)"
    if node_name == "triage":
        return f"{len(update.get('files_to_review', []))} file(s) to review, {len(update.get('skipped_files', []))} skipped"
    if node_name == "reporting":
        return f"{len(update.get('review_markdown', ''))} char review generated"
    return "completed"
import asyncio
import uuid
from app.agents.state import ReviewState, ChangedFile, Finding
from app.agents.graph import build_graph
from app.services.pipeline_runner import run_review_with_observability
from app.db.session import SessionLocal
from app.db.models import Review, PullRequest, Repository, ReviewStatus

def run():
    print("Initializing dummy data...")
    db = SessionLocal()
    
    repo = Repository(id=str(uuid.uuid4()), github_repo_id=999999, full_name="demo/vuln-repo")
    db.add(repo)
    db.commit()
    
    pr = PullRequest(
        id=str(uuid.uuid4()), 
        repository_id=repo.id, 
        number=1, 
        title="Add user search", 
        head_sha="dummy", base_sha="dummy", author_login="demo-user"
    )
    db.add(pr)
    db.commit()
    
    review = Review(
        id=str(uuid.uuid4()),
        pull_request_id=pr.id,
        triggered_sha="dummy",
        status=ReviewStatus.QUEUED
    )
    db.add(review)
    db.commit()

    state = ReviewState(
        repo_full_name="demo/vuln-repo",
        pr_number=1,
        pr_title="Add user search",
        pr_body="Adds a search endpoint",
        head_sha="dummy",
        changed_files=[],
        raw_analyzer_findings=[
            Finding(
                file_path="app/db.py",
                start_line=10,
                end_line=12,
                vulnerability_type="SQL Injection",
                severity="high",
                confidence=0.9,
                source="semgrep",
                explanation="Unsanitized user input in SQL query.",
                code_snippet='def search(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
            )
        ]
    )

    print(f"Triggering LLM Pipeline for Review ID: {review.id} ...")
    
    try:
        final_state = run_review_with_observability(state, db=db, review_id=review.id)
        
        db.refresh(review)
        print("\n--- Pipeline Completed ---")
        print(f"Total Tokens Used: {sum((run.tokens_used or 0) for run in review.agent_runs)}")
        print(f"Total Cost: ${review.total_cost_usd:.4f}")
        print(f"Findings Found: {len(review.findings)}")
        print(f"Patch Suggestions Generated: {sum(len(f.patch_suggestions) for f in review.findings)}")
        print("\nView this review on your local dashboard!")
    except Exception as e:
        print(f"Pipeline failed: {e}")

if __name__ == "__main__":
    run()

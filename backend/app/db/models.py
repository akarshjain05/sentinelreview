"""
Core relational schema for SentinelReview.

Design notes:
- Every review run is decomposed into per-agent runs (AgentRun) so the
  pipeline is fully traceable/debuggable and costs/latency are attributable
  to a specific agent, not just the review as a whole.
- Findings are separate from PatchSuggestions and VerificationRuns so a
  finding can exist (and be reported) even if no safe patch could be
  generated or verified.
- Embeddings live in their own table (pgvector column) decoupled from the
  raw KnowledgeDocument text so re-embedding with a new model doesn't
  require re-ingesting source documents.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class ReviewStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentName(str, Enum):
    TRIAGE = "triage"
    STATIC_ANALYSIS = "static_analysis"
    RETRIEVAL = "retrieval"
    CLASSIFICATION = "classification"
    FIX_SUGGESTION = "fix_suggestion"
    VERIFICATION = "verification"
    REPORTING = "reporting"


class Installation(Base):
    """A GitHub App installation on an org/user account."""
    __tablename__ = "installations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    github_installation_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    account_login: Mapped[str] = mapped_column(String, index=True)
    notify_on_findings: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    repositories: Mapped[list["Repository"]] = relationship(back_populates="installation")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    # Nullable, not cascade-deleted: if a GitHub App installation is later
    # removed, historical repositories/reviews/findings should remain
    # queryable as an audit trail, not vanish along with the installation
    # row. SQLAlchemy's default relationship behavior (orphan the child by
    # setting this to NULL) is what we want here, which requires the
    # column to actually allow NULL.
    installation_id: Mapped[str | None] = mapped_column(ForeignKey("installations.id"), nullable=True)
    github_repo_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String, index=True)  # e.g. "owner/repo"
    default_branch: Mapped[str] = mapped_column(String, default="main")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_patch_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    min_severity_to_report: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.MEDIUM)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    installation: Mapped["Installation"] = relationship(back_populates="repositories")
    pull_requests: Mapped[list["PullRequest"]] = relationship(back_populates="repository")


class PullRequest(Base):
    __tablename__ = "pull_requests"
    __table_args__ = (UniqueConstraint("repository_id", "number", name="uq_repo_pr_number"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String)
    head_sha: Mapped[str] = mapped_column(String)
    base_sha: Mapped[str] = mapped_column(String)
    author_login: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    repository: Mapped["Repository"] = relationship(back_populates="pull_requests")
    reviews: Mapped[list["Review"]] = relationship(back_populates="pull_request")


class Review(Base):
    """One review = one triggered run of the full agent pipeline against a PR at a given SHA."""
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    pull_request_id: Mapped[str] = mapped_column(ForeignKey("pull_requests.id"))
    triggered_sha: Mapped[str] = mapped_column(String)
    status: Mapped[ReviewStatus] = mapped_column(SAEnum(ReviewStatus), default=ReviewStatus.QUEUED)
    is_manual_rerun: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    total_latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    pull_request: Mapped["PullRequest"] = relationship(back_populates="reviews")
    agent_runs: Mapped[list["AgentRun"]] = relationship(back_populates="review")
    findings: Mapped[list["Finding"]] = relationship(back_populates="review")


class AgentRun(Base):
    """A single node execution within the LangGraph pipeline for a review. Powers observability."""
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id"))
    agent_name: Mapped[AgentName] = mapped_column(SAEnum(AgentName))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    input_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String, nullable=True)
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    review: Mapped["Review"] = relationship(back_populates="agent_runs")


class KnowledgeDocument(Base):
    """Raw ingested security knowledge (a CVE record, an OWASP page, a CWE entry, a GHSA advisory)."""
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_knowledge_doc_source_external_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String, index=True)  # "nvd" | "osv" | "ghsa" | "owasp" | "cwe"
    external_id: Mapped[str] = mapped_column(String, index=True)  # e.g. "CVE-2024-12345"
    title: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(Text)
    cwe_ids: Mapped[str | None] = mapped_column(String, nullable=True)  # comma-separated
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    embeddings: Mapped[list["Embedding"]] = relationship(back_populates="document")


class Embedding(Base):
    """
    Vector embedding for a chunk of a KnowledgeDocument.

    NOTE: the `vector` column is declared as Text here to keep this schema
    importable without the pgvector extension installed (e.g. in this sandbox
    or SQLite-based unit tests). In the real Postgres/Neon deployment this
    column should be `sqlalchemy.dialects.postgresql.ARRAY(Float)` or, with
    the `pgvector` python package installed, `pgvector.sqlalchemy.Vector(768)`.
    """
    __tablename__ = "embeddings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    document_id: Mapped[str] = mapped_column(ForeignKey("knowledge_documents.id"))
    chunk_index: Mapped[int] = mapped_column(Integer)
    chunk_text: Mapped[str] = mapped_column(Text)
    embedding_model: Mapped[str] = mapped_column(String)
    vector: Mapped[str] = mapped_column(Text)  # see docstring above

    document: Mapped["KnowledgeDocument"] = relationship(back_populates="embeddings")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id"))
    file_path: Mapped[str] = mapped_column(String)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    cwe_id: Mapped[str | None] = mapped_column(String, nullable=True)
    vulnerability_type: Mapped[str] = mapped_column(String)  # e.g. "sql_injection"
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity))
    confidence: Mapped[float] = mapped_column(Float)  # 0-1
    source: Mapped[str] = mapped_column(String)  # "semgrep" | "bandit" | "llm" | "combined"
    explanation: Mapped[str] = mapped_column(Text)
    code_snippet: Mapped[str] = mapped_column(Text)
    # Comma-separated KnowledgeDocument.external_id values (e.g. "CWE-89")
    # this finding's explanation is grounded in -- was silently dropped
    # during Finding persistence until now, even though the pipeline state
    # (app/agents/state.py's Finding.cited_document_ids) already carried
    # it; there was simply no column for it to land in.
    cited_document_ids: Mapped[str | None] = mapped_column(String, nullable=True)

    review: Mapped["Review"] = relationship(back_populates="findings")
    patch_suggestions: Mapped[list["PatchSuggestion"]] = relationship(back_populates="finding")


class PatchSuggestion(Base):
    __tablename__ = "patch_suggestions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    diff: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str] = mapped_column(Text)
    cited_document_ids: Mapped[str | None] = mapped_column(String, nullable=True)  # comma-separated
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    finding: Mapped["Finding"] = relationship(back_populates="patch_suggestions")
    verification_runs: Mapped[list["VerificationRun"]] = relationship(back_populates="patch_suggestion")


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    patch_suggestion_id: Mapped[str] = mapped_column(ForeignKey("patch_suggestions.id"))
    issue_resolved: Mapped[bool] = mapped_column(Boolean)
    tests_passed: Mapped[bool] = mapped_column(Boolean)
    build_succeeded: Mapped[bool] = mapped_column(Boolean)
    introduced_new_findings: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    patch_suggestion: Mapped["PatchSuggestion"] = relationship(back_populates="verification_runs")


class EvaluationResult(Base):
    """Result of running the full pipeline against a labeled benchmark (OWASP Benchmark, Juliet)."""
    __tablename__ = "evaluation_results"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    benchmark_name: Mapped[str] = mapped_column(String)  # "owasp_benchmark" | "juliet"
    pipeline_variant: Mapped[str] = mapped_column(String)  # "sentinelreview" | "semgrep_only" | "llm_only"
    precision: Mapped[float] = mapped_column(Float)
    recall: Mapped[float] = mapped_column(Float)
    f1: Mapped[float] = mapped_column(Float)
    false_positives: Mapped[int] = mapped_column(Integer)
    false_negatives: Mapped[int] = mapped_column(Integer)
    avg_latency_ms: Mapped[int] = mapped_column(Integer)
    avg_cost_usd: Mapped[float] = mapped_column(Float)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
"""
Shared state object threaded through every node of the LangGraph pipeline.

Using a single typed state (rather than passing ad-hoc dicts between agents)
is what makes the graph checkpointable, debuggable, and testable in
isolation -- each node is a pure function of (state) -> partial state update.
"""
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class ChangedFile(BaseModel):
    path: str
    diff: str
    is_test_file: bool = False
    is_doc_file: bool = False
    risk_score: float = 0.0  # set by Triage Agent, 0-1


class KnowledgeSnippet(BaseModel):
    document_id: str
    source: str  # nvd | osv | ghsa | owasp | cwe
    title: str
    text: str
    url: str | None = None
    relevance_score: float = 0.0


class PipelineFinding(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    vulnerability_type: str
    cwe_id: str | None = None
    severity: Severity = "medium"
    confidence: float = 0.0
    source: str = "combined"  # e.g. "bandit", "semgrep", "bandit+semgrep", "bandit+semgrep+classifier"
    explanation: str = ""
    code_snippet: str = ""
    cited_document_ids: list[str] = Field(default_factory=list)


class PatchSuggestion(BaseModel):
    finding_index: int  # index into state.findings
    diff: str
    reasoning: str
    cited_document_ids: list[str] = Field(default_factory=list)


class VerificationOutcome(BaseModel):
    patch_index: int  # index into state.patch_suggestions
    issue_resolved: bool
    tests_passed: bool
    build_succeeded: bool
    introduced_new_findings: bool = False
    log: str = ""

    @property
    def is_safe_to_suggest(self) -> bool:
        return self.issue_resolved and self.tests_passed and self.build_succeeded and not self.introduced_new_findings


class SecurityFlag(BaseModel):
    """Recorded whenever a guardrail catches something suspicious in untrusted PR content."""
    source: str
    matched_patterns: list[str]


class ReviewState(BaseModel):
    # Inputs
    repo_full_name: str
    pr_number: int
    pr_title: str
    pr_body: str
    head_sha: str
    changed_files: list[ChangedFile] = Field(default_factory=list)

    # Triage output
    files_to_review: list[str] = Field(default_factory=list)
    skipped_files: list[str] = Field(default_factory=list)

    # Static analysis output
    raw_analyzer_findings: list[PipelineFinding] = Field(default_factory=list)

    # Retrieval output
    retrieved_knowledge: list[KnowledgeSnippet] = Field(default_factory=list)

    # Classification output (merges/refines raw_analyzer_findings)
    findings: list[PipelineFinding] = Field(default_factory=list)

    # Fix suggestion output
    patch_suggestions: list[PatchSuggestion] = Field(default_factory=list)

    # Verification output
    verification_outcomes: list[VerificationOutcome] = Field(default_factory=list)

    # Reporting output
    review_markdown: str = ""

    # Observability / safety
    security_flags: list[SecurityFlag] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    tokens_used: int = 0
    cost_usd: float = 0.0
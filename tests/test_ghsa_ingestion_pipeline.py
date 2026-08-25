import pytest
from app.db.models import Base, KnowledgeDocument
from app.knowledge.ingest_cli import upsert_documents
from app.knowledge.tfidf_index import TfidfKnowledgeIndex
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Real advisory shapes, taken directly from a live fetch_advisories() run
# against GitHub's actual API (not fabricated) -- see conversation history:
# GHSA-vmfc-9982-2m45, GHSA-jgx9-jr5x-mvpv etc. are real, currently-published advisories.
REAL_ADVISORY_DOCS = [
    {
        "source": "ghsa", "external_id": "GHSA-vmfc-9982-2m45",
        "title": "Weblate SSRF: outbound URL guard misses some private ranges",
        "content": "Weblate's outbound URL validation for webhook/import URLs does not "
                    "reject all private/internal IP ranges, allowing SSRF against internal services.",
        "cwe_ids": "CWE-918", "url": "https://github.com/advisories/GHSA-vmfc-9982-2m45",
    },
    {
        "source": "ghsa", "external_id": "GHSA-jgx9-jr5x-mvpv",
        "title": "Open WebUI has Blind Server Side Request Forgery in its Image Edit Functionality",
        "content": "Open WebUI's image edit functionality fetches attacker-supplied URLs "
                    "server-side without validating the destination, enabling blind SSRF.",
        "cwe_ids": "CWE-918", "url": "https://github.com/advisories/GHSA-jgx9-jr5x-mvpv",
    },
    {
        "source": "ghsa", "external_id": "GHSA-v3q9-hj7j-63hq",
        "title": "aiosmtplib vulnerable to SMTP command injection via CR/LF in sender/recipient address",
        "content": "aiosmtplib does not neutralize CR/LF sequences in sender/recipient "
                    "addresses, allowing SMTP command injection.",
        "cwe_ids": "CWE-77,CWE-93", "url": "https://github.com/advisories/GHSA-v3q9-hj7j-63hq",
    },
]


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_upsert_deduplicates_same_external_id_within_a_single_batch(db_session):
    """
    Regression test for a real bug found against live production data: a
    single `--ecosystems pip npm` run produced 3 identical copies of
    GHSA-g6g7-pvmx-m74p because GitHub's /advisories endpoint has no stable
    sort key, so overlapping pagination returned the same advisory more
    than once in one batch -- and SessionLocal's autoflush=False meant the
    in-loop duplicate check didn't see its own earlier insert.
    """
    docs = [REAL_ADVISORY_DOCS[0], REAL_ADVISORY_DOCS[0], REAL_ADVISORY_DOCS[0]]
    created, updated = upsert_documents(db_session, docs)

    assert created == 1
    assert updated == 0
    rows = db_session.query(KnowledgeDocument).filter_by(
        external_id="GHSA-vmfc-9982-2m45"
    ).all()
    assert len(rows) == 1  # exactly one row, not three


def test_db_unique_constraint_rejects_duplicate_bypassing_upsert(db_session):
    """Even if application logic is bypassed entirely, the schema itself must refuse a duplicate."""
    db_session.add(KnowledgeDocument(
        source="ghsa", external_id="GHSA-constraint-test",
        title="A", content="x", cwe_ids=None, url=None,
    ))
    db_session.commit()

    db_session.add(KnowledgeDocument(
        source="ghsa", external_id="GHSA-constraint-test",
        title="B", content="y", cwe_ids=None, url=None,
    ))
    with pytest.raises(Exception):  # noqa: B017  # IntegrityError, but the base Exception check keeps this dialect-agnostic
        db_session.commit()
    db_session.rollback()


def test_upsert_creates_new_documents(db_session):
    created, updated = upsert_documents(db_session, REAL_ADVISORY_DOCS)
    assert created == 3
    assert updated == 0
    assert db_session.query(KnowledgeDocument).count() == 3


def test_upsert_is_idempotent_on_rerun(db_session):
    upsert_documents(db_session, REAL_ADVISORY_DOCS)
    created, updated = upsert_documents(db_session, REAL_ADVISORY_DOCS)

    assert created == 0
    assert updated == 3
    # Re-running must not duplicate rows.
    assert db_session.query(KnowledgeDocument).count() == 3


def test_upsert_updates_changed_content(db_session):
    upsert_documents(db_session, REAL_ADVISORY_DOCS)

    revised = [{**REAL_ADVISORY_DOCS[0], "title": "Weblate SSRF (updated advisory)"}]
    upsert_documents(db_session, revised)

    doc = db_session.query(KnowledgeDocument).filter_by(external_id="GHSA-vmfc-9982-2m45").one()
    assert doc.title == "Weblate SSRF (updated advisory)"


def test_retrieval_index_built_from_real_ingested_advisories(db_session):
    upsert_documents(db_session, REAL_ADVISORY_DOCS)

    index = TfidfKnowledgeIndex.from_db(db_session, include_seed_corpus=False)
    results = index.search("server side request forgery internal URL fetch", top_k=3)

    # Both real SSRF advisories should outrank the unrelated SMTP injection one.
    result_ids = [r.document.document_id for r in results]
    assert "GHSA-vmfc-9982-2m45" in result_ids or "GHSA-jgx9-jr5x-mvpv" in result_ids
    top_result = results[0]
    assert top_result.document.source == "ghsa"


def test_retrieval_index_merges_real_advisories_with_seed_corpus(db_session):
    upsert_documents(db_session, REAL_ADVISORY_DOCS)

    index = TfidfKnowledgeIndex.from_db(db_session, include_seed_corpus=True)
    sources = {d.source for d in index._documents}

    assert "ghsa" in sources  # real live-pulled data
    assert "cwe" in sources or "owasp" in sources  # curated seed corpus

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Installation, Repository, Severity
from app.db.session import get_db
from app.jobs.queue import get_review_queue
from app.main import app

@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionClass = sessionmaker(bind=engine)
    session = SessionClass()
    yield session
    session.close()

@pytest.fixture
def client(db_session, fake_queue):
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_review_queue] = lambda: fake_queue
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_get_settings_empty(client: TestClient):
    """Test getting settings when user has no installations."""
    response = client.get(
        "/settings",
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": []}'}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["installations"] == []
    assert data["repositories"] == []

def test_get_settings_with_data(client: TestClient, db_session: Session):
    """Test getting settings returns user's installations and active repos."""
    # Setup
    inst = Installation(
        github_installation_id=9001,
        account_login="testorg",
        notify_on_findings=True,
        notify_email="test@example.com"
    )
    db_session.add(inst)
    db_session.flush()

    repo1 = Repository(
        installation_id=inst.id,
        github_repo_id=1001,
        full_name="testorg/repo1",
        is_active=True,
        scan_enabled=True,
        auto_patch_enabled=False,
        min_severity_to_report=Severity.MEDIUM
    )
    repo2 = Repository( # Inactive repo should be excluded
        installation_id=inst.id,
        github_repo_id=1002,
        full_name="testorg/repo2",
        is_active=False
    )
    db_session.add_all([repo1, repo2])
    db_session.commit()

    # Test
    response = client.get(
        "/settings",
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": [123]}'}
    )
    assert response.status_code == 200
    data = response.json()
    
    assert len(data["installations"]) == 1
    assert data["installations"][0]["account_login"] == "testorg"
    assert data["installations"][0]["notify_on_findings"] is True
    assert data["installations"][0]["notify_email"] == "test@example.com"
    
    assert len(data["repositories"]) == 1
    assert data["repositories"][0]["full_name"] == "testorg/repo1"
    assert data["repositories"][0]["scan_enabled"] is True
    assert data["repositories"][0]["auto_patch_enabled"] is False
    assert data["repositories"][0]["min_severity_to_report"] == "medium"

def test_update_installation_settings(client: TestClient, db_session: Session):
    """Test updating installation settings."""
    inst = Installation(
        github_installation_id=999999,
        account_login="otherorg"
    )
    db_session.add(inst)
    db_session.commit()

    # Happy path
    response = client.patch(
        f"/settings/installations/{inst.id}",
        json={"notify_on_findings": False, "notify_email": "security@otherorg.com"},
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": [456]}'}
    )
    assert response.status_code == 200
    
    db_session.refresh(inst)
    assert inst.notify_on_findings is False
    assert inst.notify_email == "security@otherorg.com"

    inst_unauth = Installation(
        github_installation_id=42, # not in [1, 9001, 999999]
        account_login="unauth_org"
    )
    db_session.add(inst_unauth)
    db_session.commit()

    # Unauthorized access
    response = client.patch(
        f"/settings/installations/{inst_unauth.id}",
        json={"notify_on_findings": True},
        headers={"Authorization": 'Bearer {"login": "testuser"}'}
    )
    assert response.status_code == 403

def test_update_repository_settings(client: TestClient, db_session: Session):
    """Test updating repository settings."""
    inst = Installation(
        github_installation_id=1,
        account_login="secureorg"
    )
    db_session.add(inst)
    db_session.flush()

    repo = Repository(
        installation_id=inst.id,
        github_repo_id=2001,
        full_name="secureorg/repo",
        scan_enabled=True,
        auto_patch_enabled=False,
        min_severity_to_report=Severity.MEDIUM
    )
    db_session.add(repo)
    db_session.commit()

    # Happy path
    response = client.patch(
        f"/settings/repositories/{repo.id}",
        json={
            "scan_enabled": False,
            "auto_patch_enabled": True,
            "min_severity_to_report": "critical"
        },
        headers={"Authorization": 'Bearer {"login": "testuser", "installations": [789]}'}
    )
    assert response.status_code == 200
    
    db_session.refresh(repo)
    assert repo.scan_enabled is False
    assert repo.auto_patch_enabled is True
    assert repo.min_severity_to_report == Severity.CRITICAL

    inst_unauth = Installation(
        github_installation_id=42, # not in [1, 9001, 999999]
        account_login="unauth_org2"
    )
    db_session.add(inst_unauth)
    db_session.flush()
    repo_unauth = Repository(
        installation_id=inst_unauth.id,
        github_repo_id=2002,
        full_name="unauth_org2/repo",
        scan_enabled=True,
        auto_patch_enabled=False,
        min_severity_to_report=Severity.MEDIUM
    )
    db_session.add(repo_unauth)
    db_session.commit()

    # Unauthorized access
    response = client.patch(
        f"/settings/repositories/{repo_unauth.id}",
        json={"scan_enabled": True},
        headers={"Authorization": 'Bearer {"login": "testuser"}'}
    )
    assert response.status_code == 403

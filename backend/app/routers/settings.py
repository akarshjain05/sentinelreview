from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.oauth import get_current_user
from app.db.models import Installation, Repository, Severity
from app.db.session import get_db

router = APIRouter(prefix="/settings", tags=["settings"])

class InstallationSettingsUpdate(BaseModel):
    notify_on_findings: bool | None = None
    notify_email: str | None = None

class RepositorySettingsUpdate(BaseModel):
    is_active: bool | None = None
    scan_enabled: bool | None = None
    auto_patch_enabled: bool | None = None
    min_severity_to_report: Severity | None = None

@router.get("")
def get_settings(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Fetch current user's installations and repos with their configuration states."""
    installation_ids = user.get("installations", [])
    if not installation_ids:
        return {"installations": [], "repositories": []}

    installations = db.query(Installation).filter(Installation.github_installation_id.in_(installation_ids)).all()
    inst_ids = [inst.id for inst in installations]
    
    repositories = db.query(Repository).filter(Repository.installation_id.in_(inst_ids), Repository.is_active == True).all()

    return {
        "installations": [
            {
                "id": inst.id,
                "account_login": inst.account_login,
                "notify_on_findings": inst.notify_on_findings,
                "notify_email": inst.notify_email,
            }
            for inst in installations
        ],
        "repositories": [
            {
                "id": repo.id,
                "full_name": repo.full_name,
                "scan_enabled": repo.scan_enabled,
                "auto_patch_enabled": repo.auto_patch_enabled,
                "min_severity_to_report": repo.min_severity_to_report,
            }
            for repo in repositories
        ]
    }

@router.patch("/installations/{installation_id}")
def update_installation_settings(
    installation_id: str, 
    update: InstallationSettingsUpdate,
    user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    inst = db.query(Installation).filter(Installation.id == installation_id).first()
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")
        
    # Security: Verify the user has access to this installation
    if inst.github_installation_id not in user.get("installations", []):
        raise HTTPException(status_code=403, detail="Not authorized")

    update_data = update.model_dump(exclude_unset=True) if hasattr(update, "model_dump") else update.dict(exclude_unset=True)
    if "notify_on_findings" in update_data:
        inst.notify_on_findings = update_data["notify_on_findings"]
    if "notify_email" in update_data:
        inst.notify_email = update_data["notify_email"]

    db.commit()
    db.refresh(inst)
    return {"status": "ok"}

@router.patch("/repositories/{repository_id}")
def update_repository_settings(
    repository_id: str, 
    update: RepositorySettingsUpdate,
    user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    repo = db.query(Repository).filter(Repository.id == repository_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Security: Verify access via the parent installation
    if not repo.installation or repo.installation.github_installation_id not in user.get("installations", []):
        raise HTTPException(status_code=403, detail="Not authorized")

    update_data = update.model_dump(exclude_unset=True) if hasattr(update, "model_dump") else update.dict(exclude_unset=True)
    if "is_active" in update_data:
        repo.is_active = update_data["is_active"]
    if "scan_enabled" in update_data:
        repo.scan_enabled = update_data["scan_enabled"]
    if "auto_patch_enabled" in update_data:
        repo.auto_patch_enabled = update_data["auto_patch_enabled"]
    if "min_severity_to_report" in update_data:
        repo.min_severity_to_report = update_data["min_severity_to_report"]

    db.commit()
    db.refresh(repo)
    return {"status": "ok"}

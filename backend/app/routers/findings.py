from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import VulnFinding

router = APIRouter(prefix="/findings", tags=["findings"])

@router.get("")
def list_findings(asset_id: int | None = None, limit: int = 500):
    db: Session = next(get_db())
    q = select(VulnFinding).order_by(VulnFinding.id.desc())
    if asset_id:
        q = q.where(VulnFinding.asset_id == asset_id)
    rows = db.execute(q).scalars().all()
    return [{
        "id": r.id,
        "asset_id": r.asset_id,
        "software_id": r.software_id,
        "cve": r.cve_id,
        "severity": r.severity,
        "cvss": r.cvss,
        "kev": r.kev,
        "product": r.product,
        "detected_version": r.detected_version,
    } for r in rows[:limit]]

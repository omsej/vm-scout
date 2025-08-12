from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from ..db import get_db
from ..models import Software, Asset

router = APIRouter(prefix="/software", tags=["software"])

@router.get("/by-asset/{asset_id}")
def list_software(asset_id: int, limit: int = 300, db: Session = Depends(get_db)):
    if not db.get(Asset, asset_id):
        raise HTTPException(404, "asset not found")
    rows = db.execute(select(Software).where(Software.asset_id==asset_id).order_by(Software.name)).scalars().all()
    out = [{"id": s.id, "name": s.name, "version": s.version, "publisher": s.publisher} for s in rows[:limit]]
    return out

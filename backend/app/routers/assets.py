from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Asset, Software, Service
from ..schemas import AssetOut

router = APIRouter(prefix="/assets", tags=["assets"])

@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    rows = db.execute(select(Asset)).scalars().all()
    return rows

@router.get("/summary")
def asset_summary(db: Session = Depends(get_db)):
    count_assets = db.scalar(select(func.count()).select_from(Asset)) or 0
    count_sw = db.scalar(select(func.count()).select_from(Software)) or 0
    count_svcs = db.scalar(select(func.count()).select_from(Service)) or 0
    return {"assets": count_assets, "software": count_sw, "services": count_svcs}

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..services.feed_nvd import update_nvd
from ..services.feed_kev import update_kev

router = APIRouter(prefix="/feeds", tags=["feeds"])

@router.post("/nvd")
def refresh_nvd(days: int = 30, db: Session = Depends(get_db)):
    count = update_nvd(db, days=days)
    return {"status": "ok", "cves_upserted": count, "days": days}

@router.post("/kev")
def refresh_kev(db: Session = Depends(get_db)):
    count = update_kev(db)
    return {"status": "ok", "kev_marked": count}

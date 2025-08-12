from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..services.matcher import match_all, match_asset

router = APIRouter(prefix="/match", tags=["match"])

@router.post("/run")
def run_match(asset_id: int | None = None, db: Session = Depends(get_db)):
    if asset_id:
        n = match_asset(db, asset_id)
        return {"status":"ok", "asset_id": asset_id, "findings": n}
    n = match_all(db)
    return {"status":"ok", "assets_processed": n["assets"], "findings_created": n["findings"]}

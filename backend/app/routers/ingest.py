from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from datetime import datetime
from ..db import get_db
from ..models import Asset, Software, Service
from ..schemas import InventoryPayload, OSInfo

router = APIRouter(prefix="/ingest", tags=["ingest"])

@router.post("/inventory")
def ingest_inventory(payload: InventoryPayload, db: Session = Depends(get_db)):
    hostname = payload.hostname.strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname required")

    # Upsert asset
    asset = db.execute(select(Asset).where(Asset.hostname == hostname)).scalar_one_or_none()
    if not asset:
        asset = Asset(hostname=hostname)
        db.add(asset)
        db.flush()

    # OS fields
    os_in = payload.os if isinstance(payload.os, OSInfo) else OSInfo(**payload.os)
    asset.os_name = os_in.name
    asset.os_version = os_in.version
    asset.os_build = os_in.build
    asset.updated_at = datetime.utcnow()
    db.flush()

    # Replace software/services snapshot for this run
    db.execute(delete(Software).where(Software.asset_id == asset.id))
    db.execute(delete(Service).where(Service.asset_id == asset.id))
    db.flush()

    # Insert software
    for s in payload.software:
        db.add(Software(
            asset_id=asset.id,
            name=s.name.strip()[:512],
            version=(s.version or "").strip()[:128] or None,
            publisher=(s.publisher or "").strip()[:256] or None,
        ))

    # Insert services
    for sv in payload.services:
        db.add(Service(
            asset_id=asset.id,
            protocol=(sv.protocol or "").upper()[:10] or None,
            local_address=(sv.local_address or None),
            local_port=sv.local_port,
            process=(sv.process or None),
            banner=(sv.banner or None),
        ))

    db.commit()
    return {"status": "ingested", "asset_id": asset.id, "software": len(payload.software), "services": len(payload.services)}

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

# -------- Inbound payloads (from collector) ----------
class OSInfo(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    build: Optional[str] = None

class SoftwareItem(BaseModel):
    name: str
    version: Optional[str] = None
    publisher: Optional[str] = None

class ServiceItem(BaseModel):
    protocol: Optional[str] = None
    local_address: Optional[str] = None
    local_port: int
    process: Optional[str] = None
    banner: Optional[str] = None

class InventoryPayload(BaseModel):
    hostname: str
    collected_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    os: OSInfo | dict
    software: List[SoftwareItem] = []
    services: List[ServiceItem] = []

# -------- Outbound / API schemas ----------
class AssetOut(BaseModel):
    id: int
    hostname: str
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_build: Optional[str] = None

    class Config:
        from_attributes = True

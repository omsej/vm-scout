from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base
from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, Boolean, Text, Float

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_build: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(50), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    software: Mapped[list["Software"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

class Software(Base):
    __tablename__ = "software"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cpe_guess: Mapped[str | None] = mapped_column(String(512), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="software")
    __table_args__ = (UniqueConstraint("asset_id", "name", "version", name="uix_asset_software"),)

class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    local_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    local_port: Mapped[int] = mapped_column(Integer)
    process: Mapped[str | None] = mapped_column(String(256), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="services")
    __table_args__ = (UniqueConstraint("asset_id", "protocol", "local_address", "local_port", name="uix_asset_service"),)

# --- NEW: CVE + CPE + KEV + Findings ---

class CVE(Base):
    __tablename__ = "cves"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g., CVE-2025-1234
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    published: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)

    cpes: Mapped[list["CVECPE"]] = relationship(back_populates="cve", cascade="all, delete-orphan")

class CVECPE(Base):
    __tablename__ = "cve_cpes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    cpe23: Mapped[str] = mapped_column(String(512), index=True)  # cpe:2.3:a:vendor:product:version:...
    vendor: Mapped[str | None] = mapped_column(String(128), index=True)
    product: Mapped[str | None] = mapped_column(String(256), index=True)
    vers_start_incl: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vers_start_excl: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vers_end_incl:   Mapped[str | None] = mapped_column(String(64), nullable=True)
    vers_end_excl:   Mapped[str | None] = mapped_column(String(64), nullable=True)

    cve: Mapped["CVE"] = relationship(back_populates="cpes")

class VulnFinding(Base):
    __tablename__ = "vuln_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    software_id: Mapped[int | None] = mapped_column(ForeignKey("software.id", ondelete="SET NULL"), nullable=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detected_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("asset_id","software_id","cve_id", name="uix_asset_sw_cve"),)

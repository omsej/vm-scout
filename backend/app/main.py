# backend/app/main.py
from fastapi import FastAPI
from .db import engine, Base
from . import models  # ensure models are imported so tables are registered
from .routers import health, assets, ingest, feeds, match, findings, software

def create_app() -> FastAPI:
    app = FastAPI(title="vm-scout API", version="0.2.0")
    # Routers
    app.include_router(health.router)
    app.include_router(assets.router)
    app.include_router(ingest.router)
    app.include_router(feeds.router)
    app.include_router(match.router)
    app.include_router(findings.router)
    app.include_router(software.router)
    return app

app = create_app()

# Create tables on startup (dev convenience)
Base.metadata.create_all(bind=engine)

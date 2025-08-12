from fastapi import FastAPI
from .db import engine, Base
from . import models
from .routers import health, assets, ingest, feeds, match, findings

def create_app() -> FastAPI:
    app = FastAPI(title="vm-scout API", version="0.1.0")
    app.include_router(health.router)
    app.include_router(assets.router)
    app.include_router(ingest.router)
    return app

app = create_app()

@staticmethod
def _init_db():
    Base.metadata.create_all(bind=engine)

_init_db()

def create_app() -> FastAPI:
    app = FastAPI(title="vm-scout API", version="0.2.0")
    app.include_router(health.router)
    app.include_router(assets.router)
    app.include_router(ingest.router)
    app.include_router(feeds.router)
    app.include_router(match.router)
    return app

app = create_app()

Base.metadata.create_all(bind=engine)

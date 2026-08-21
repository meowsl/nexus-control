"""FastAPI application: operator console API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from nexus_control.web.db import init_db
from nexus_control.web.routers import (
    auth,
    history,
    integrations,
    jobs,
    labels,
    repos,
    schedule,
    status,
)

app = FastAPI(
    title="Nexus Control",
    version="0.6.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth.router, prefix="/api")
app.include_router(status.router, prefix="/api")
app.include_router(repos.router, prefix="/api")
app.include_router(labels.router, prefix="/api")
app.include_router(jobs.router, prefix="/api")
app.include_router(schedule.router, prefix="/api")
app.include_router(history.router, prefix="/api")
app.include_router(integrations.router, prefix="/api")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

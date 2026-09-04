from __future__ import annotations

from fastapi import FastAPI

from backend.app.api.routes_events import router as events_router
from backend.app.api.routes_investigate import router as investigate_router

app = FastAPI(title="Blackbox", version="0.1.0")
app.include_router(events_router)
app.include_router(investigate_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

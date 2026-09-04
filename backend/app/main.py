from __future__ import annotations

from fastapi import FastAPI

from app.api.routes_events import router as events_router

app = FastAPI(title="Blackbox", version="0.1.0")
app.include_router(events_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

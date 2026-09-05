from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes_events import router as events_router
from backend.app.api.routes_incidents import router as incidents_router
from backend.app.api.routes_investigate import router as investigate_router

app = FastAPI(title="REDBLUE", version="0.1.0")

# Configure CORS for deployment (supporting FRONTEND_URL environment variable)
frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5173")
origins = [origin.strip() for origin in frontend_url.split(",") if origin.strip()]
for default_origin in ["http://localhost:5173", "http://localhost:4173", "http://127.0.0.1:5173"]:
    if default_origin not in origins:
        origins.append(default_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events_router)
app.include_router(investigate_router)
app.include_router(incidents_router)


@app.middleware("http")
async def strip_api_prefix(request: Request, call_next):
    path = request.scope.get("path", "")
    if path.startswith("/api/") and path != "/api/":
        request.scope["path"] = path[4:]
    return await call_next(request)



@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("backend.app.main:app", host=host, port=port)


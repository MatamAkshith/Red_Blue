"""Vercel Serverless Function entrypoint for REDBLUE FastAPI backend."""

import sys
from pathlib import Path

# Add repository root to sys.path so 'backend.app.main' imports resolve cleanly on Vercel
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app

# Export app as ASGI handler for Vercel
app = app

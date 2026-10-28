import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.database import ensure_schema
from app.routes.scan import router as scan_router

logging.basicConfig(level=logging.INFO)

# Comma-separated list of dashboard origins allowed to call the API.
# Defaults cover the Vite dev server. The Chrome extension calls the API
# through its host_permissions and does not need an origin entry here.
DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CHAINSHIELD_CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]

# Schema setup runs when the server starts, not at import, so importing the app
# (tests, tools) never touches the database. app/server.py adds its own hook.
STARTUP_HOOKS = [ensure_schema]


@asynccontextmanager
async def lifespan(_app):
    for hook in STARTUP_HOOKS:
        hook()
    yield


app = FastAPI(title="ChainShield API", lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def home():
    return {"message": "ChainShield Backend is Running!"}


app.include_router(scan_router)

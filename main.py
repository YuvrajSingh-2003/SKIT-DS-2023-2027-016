import logging
import os

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

app = FastAPI(title="ChainShield API")


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

# Runs after the models are imported so every table is created.
ensure_schema()

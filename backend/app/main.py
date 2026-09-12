import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.emails import router as emails_router
from app.api.health import router as health_router
from app.api.cases import router as cases_router
from app.config import validate_ai_configuration

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    valid, msg = validate_ai_configuration()
    if valid:
        logger.info("DetectThreatAI startup: %s", msg)
    else:
        logger.error("DetectThreatAI STARTUP CONFIGURATION ALERT: %s", msg)
    yield


app = FastAPI(title="DetectThreatAI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://detect-threat-ai2.vercel.app",
        "https://detect-threat-ai.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(emails_router, prefix="/api")
app.include_router(cases_router, prefix="/api")

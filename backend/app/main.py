from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.emails import router as emails_router
from app.api.health import router as health_router
from app.api.cases import router as cases_router

app = FastAPI(title="DetectThreatAI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(emails_router, prefix="/api")
app.include_router(cases_router, prefix="/api")

from typing import Any
from fastapi import APIRouter

from app.config import validate_ai_configuration

router = APIRouter()


@router.get("/health")
def health_check() -> dict[str, Any]:
    valid, _ = validate_ai_configuration()
    return {
        "status": "ok",
        "service": "DetectThreatAI",
        "ai_ready": valid,
    }


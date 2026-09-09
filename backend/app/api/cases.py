"""FastAPI API endpoints for Completed Cases Management."""

from typing import Any
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.case import CaseRecordSchema, CaseStatusUpdateSchema
from app.services.case_storage import (
    get_case_by_id,
    list_cases,
    update_case_status,
)

router = APIRouter()


@router.get("/cases", response_model=list[CaseRecordSchema])
async def get_all_cases(
    search: str | None = Query(default=None, description="Search by subject, sender, IOC, or ID"),
    verdict: str | None = Query(default=None, description="Filter by classification/verdict"),
    case_status: str | None = Query(default=None, alias="status", description="Filter by case status"),
) -> list[dict[str, Any]]:
    """Retrieve all completed cases with optional search and filtering."""
    return list_cases(search=search, verdict=verdict, status=case_status)


@router.get("/cases/{case_id}", response_model=CaseRecordSchema)
async def get_case(case_id: str) -> dict[str, Any]:
    """Retrieve a single completed case by ID.

    Guarantees read-only retrieval of previously stored investigation data.
    Does NOT trigger re-analysis, AI agent execution, or external intelligence lookups.
    """
    record = get_case_by_id(case_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case identifier '{case_id}' was not found in completed cases.",
        )
    return record


@router.patch("/cases/{case_id}/status", response_model=dict[str, Any])
async def update_status(case_id: str, payload: CaseStatusUpdateSchema) -> dict[str, Any]:
    """Update workflow status of a completed case."""
    success = update_case_status(case_id, payload.status)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' was not found.",
        )
    record = get_case_by_id(case_id)
    return record or {"status": payload.status}

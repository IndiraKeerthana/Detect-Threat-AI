"""Pydantic schemas for Completed Case Management."""

from typing import Any, Literal
from pydantic import BaseModel, Field

from app.schemas.email import EmailAnalysisResponse

CaseStatus = Literal["OPEN", "IN REVIEW", "CONTAINED", "CLOSED"]
CaseSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class CaseRecordSchema(BaseModel):
    id: str
    caseNumber: str | None = None
    title: str
    subject: str
    sender: str
    recipient: str
    severity: CaseSeverity
    classification: str
    riskScore: int = Field(ge=0, le=100)
    confidence: Literal["high", "medium", "low", "unknown"] = "medium"
    status: CaseStatus = "OPEN"
    createdAt: str
    updatedAt: str
    sourceIp: str
    analystNotes: str | None = None
    investigationData: EmailAnalysisResponse | dict[str, Any]


class CaseSummarySchema(BaseModel):
    id: str
    caseNumber: str | None = None
    title: str
    subject: str
    sender: str
    recipient: str
    severity: CaseSeverity
    classification: str
    riskScore: int
    confidence: str
    status: CaseStatus
    createdAt: str
    updatedAt: str
    sourceIp: str


class CaseStatusUpdateSchema(BaseModel):
    status: CaseStatus

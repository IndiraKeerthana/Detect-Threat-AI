"""Strict models exchanged by the Step 7 agent.

These models are intentionally small and contain only normalized evidence.  They
are also the boundary at which untrusted provider output is validated.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.investigation import AttributionAssessment, Confidence, RiskLevel, ThreatClassification


class AIAttribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["not_attributed", "infrastructure_only", "limited_attribution"]
    assessment: str
    confidence: Confidence = "unknown"
    supporting_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AIFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    explanation: str
    evidence: list[str] = Field(default_factory=list)


class AIToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""
    target: str | None = None
    iteration: int | None = None
    status: str = "success"


class AIInvestigationResult(BaseModel):
    """The only provider result exposed through the API."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    risk_level: RiskLevel
    classification: ThreatClassification
    confidence: Confidence
    reasoning: str
    key_findings: list[AIFinding] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    attribution: AIAttribution
    evidence: list[str] = Field(default_factory=list)
    tool_calls: list[AIToolCall] = Field(default_factory=list)
    iterations: int = Field(default=0, ge=0, le=20)
    source: Literal["ai_agent", "deterministic_fallback"]

    def safe_attribution(self) -> AttributionAssessment:
        """Convert to the existing attribution contract without overclaiming."""
        if self.attribution.status == "not_attributed":
            return AttributionAssessment(
                status="not_attributed",
                assessment=self.attribution.assessment,
                confidence=self.attribution.confidence,
                supporting_evidence=self.attribution.supporting_evidence,
                limitations=self.attribution.limitations,
            )
        return AttributionAssessment(
            status=self.attribution.status,
            assessment=self.attribution.assessment,
            confidence=self.attribution.confidence,
            supporting_evidence=self.attribution.supporting_evidence,
            limitations=[
                *self.attribution.limitations,
                "Infrastructure evidence does not identify or attribute a human actor.",
            ],
        )

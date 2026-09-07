"""Deterministic investigation summary with a safe structured fallback."""

from __future__ import annotations

from collections.abc import Callable
import logging
from typing import Literal, cast

from app.schemas.investigation import (
    AttributionAssessment,
    EvidenceGraph,
    InvestigationSummary,
    RiskAssessment,
)

logger = logging.getLogger(__name__)


class InvestigationSummaryService:
    """Renderer boundary accepting structured evidence only.

    A future AI renderer may receive the three typed arguments below.  Raw
    email text, headers, attachment content, and attachment bytes are
    intentionally not part of this interface.
    """

    def __init__(self, renderer: Callable[..., InvestigationSummary] | None = None) -> None:
        self.renderer = renderer

    def summarize(
        self,
        risk_assessment: RiskAssessment,
        attribution: AttributionAssessment,
        evidence_graph: EvidenceGraph,
    ) -> InvestigationSummary:
        if self.renderer is not None:
            try:
                result = self.renderer(risk_assessment, attribution, evidence_graph)
                if isinstance(result, InvestigationSummary):
                    return result
            except Exception as exc:
                # Do not log renderer arguments or exception text: either may
                # contain secrets copied from an external integration.
                logger.warning("Structured investigation renderer failed (%s)", type(exc).__name__)
            return deterministic_summary(
                risk_assessment, attribution, evidence_graph, source="fallback"
            )
        return deterministic_summary(
            risk_assessment, attribution, evidence_graph, source="deterministic"
        )


def deterministic_summary(
    risk_assessment: RiskAssessment,
    attribution: AttributionAssessment,
    evidence_graph: EvidenceGraph,
    *,
    source: str = "deterministic",
) -> InvestigationSummary:
    """Render only bounded, structured values; never accepts raw email text."""
    codes = [item.code for item in risk_assessment.factors]
    findings: list[str] = []
    if codes:
        findings.append("Risk factors: " + ", ".join(codes[:8]) + ".")
    if evidence_graph.edges:
        findings.append(f"Evidence graph contains {len(evidence_graph.edges)} supported relationship(s).")
    if attribution.status != "not_attributed":
        findings.append("Infrastructure links are investigative leads, not actor attribution.")
    if not findings:
        findings.append("No material evidence-backed threat finding was detected.")
    title = {
        "benign": "No material threat indicators",
        "low": "Low-risk message requiring routine review",
        "medium": "Message requires review before action",
        "high": "High-risk message",
        "critical": "Critical-risk message",
    }[risk_assessment.level]
    return InvestigationSummary(
        title=title,
        summary=" ".join(findings),
        risk_level=risk_assessment.level,
        confidence=risk_assessment.confidence.level,
        key_findings=findings,
        limitations=[*risk_assessment.confidence.limitations, *attribution.limitations],
        source=cast(Literal["deterministic", "fallback"], source),
    )


def build_investigation_summary(
    risk_assessment: RiskAssessment,
    attribution: AttributionAssessment,
    evidence_graph: EvidenceGraph,
) -> InvestigationSummary:
    return InvestigationSummaryService().summarize(
        risk_assessment, attribution, evidence_graph
    )


generate_investigation_summary = build_investigation_summary

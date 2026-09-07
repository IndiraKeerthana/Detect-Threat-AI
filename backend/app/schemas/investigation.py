"""Provider-neutral Step 6 investigation models.

These models intentionally describe only normalized evidence already produced by
the parser, security services, relay analysis, and Step 5 providers.
"""

from typing import Literal

from pydantic import BaseModel, Field


Confidence = Literal["high", "medium", "low", "unknown"]
RiskLevel = Literal["benign", "low", "medium", "high", "critical"]
ThreatClassification = Literal["benign", "phishing", "bec", "mixed", "suspicious"]
GraphNodeType = Literal[
    "email",
    "identity",
    "ip",
    "domain",
    "url",
    "country",
    "region",
    "city",
    "asn",
    "location",
    "provider",
    "indicator",
    "provider_observation",
]


class Correlation(BaseModel):
    code: str
    relationship: str
    explanation: str
    evidence: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    confidence: Confidence = "medium"
    sources: list[str] = Field(default_factory=list)


class EvidenceGraphNode(BaseModel):
    id: str
    type: GraphNodeType
    value: str
    sources: list[str] = Field(default_factory=list)
    properties: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    providers: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence = "medium"
    properties: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class EvidenceGraph(BaseModel):
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)


class RiskFactor(BaseModel):
    code: str
    title: str
    contribution: int = Field(ge=0, le=100)
    severity: Literal["info", "low", "medium", "high", "critical"]
    explanation: str
    evidence: list[str] = Field(default_factory=list)
    source: str = "security_analysis"
    sources: list[str] = Field(default_factory=list)
    category: str = "unknown"


class ConfidenceFactor(BaseModel):
    """A coverage/quality assessment that is deliberately not a risk signal."""

    category: Literal[
        "authentication",
        "content",
        "url",
        "infrastructure",
        "reputation",
        "registration/DNS",
        "correlation",
    ]
    level: Confidence = "unknown"
    explanation: str
    evidence_count: int = Field(ge=0, default=0)
    evidence: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class ConfidenceAssessment(BaseModel):
    level: Confidence
    explanation: str
    evidence_count: int = Field(ge=0)
    limitations: list[str] = Field(default_factory=list)
    factors: list[ConfidenceFactor] = Field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        """Compatibility view for consumers that only need category names."""
        return [item.category for item in self.factors]


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    classification: ThreatClassification = "benign"
    threat_types: list[str] = Field(default_factory=list)
    factors: list[RiskFactor] = Field(default_factory=list)
    rationale: str
    confidence: ConfidenceAssessment

    @property
    def risk_score(self) -> int:
        """Compatibility spelling for consumers that call the value risk_score."""
        return self.score

    @property
    def risk_level(self) -> RiskLevel:
        return self.level


class AttributionAssessment(BaseModel):
    status: Literal["not_attributed", "infrastructure_only", "limited_attribution"]
    assessment: str
    confidence: Confidence
    supporting_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    code: str
    priority: Literal["routine", "recommended", "urgent"]
    action: str = ""
    rationale: str = ""
    evidence: list[str] = Field(default_factory=list)
    title: str = ""
    reason: str = ""
    source: str = "security_analysis"


class InvestigationSummary(BaseModel):
    title: str
    summary: str
    risk_level: RiskLevel
    confidence: Confidence
    key_findings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    source: Literal["deterministic", "fallback"] = "deterministic"


class InvestigationAnalysis(BaseModel):
    """Complete additive Step 6 result, also exposed as individual fields."""

    correlations: list[Correlation] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    risk_assessment: RiskAssessment
    attribution: AttributionAssessment
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    investigation_summary: InvestigationSummary

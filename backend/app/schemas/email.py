from pydantic import BaseModel, ConfigDict, Field

from app.schemas.investigation import (
    AttributionAssessment,
    ConfidenceAssessment,
    Correlation,
    EvidenceGraph,
    InvestigationAnalysis,
    InvestigationSummary,
    RecommendedAction,
    RiskAssessment,
)
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence


class AttachmentMetadata(BaseModel):
    filename: str | None
    content_type: str
    size: int


class ExtractedIP(BaseModel):
    address: str
    version: int
    classification: str
    is_public_source_candidate: bool
    hop_number: int


class RelayHop(BaseModel):
    hop_number: int
    original_header: str
    hostnames: list[str]
    extracted_ips: list[ExtractedIP]


class CandidateSourceIP(BaseModel):
    address: str | None
    confidence: str
    reason: str


class RelayAnalysisMetadata(BaseModel):
    received_header_count: int
    input_header_order: str
    reconstructed_order: str
    source_selection_scope: str


class RelayAnalysis(BaseModel):
    relay_hops: list[RelayHop]
    extracted_ips: list[ExtractedIP]
    probable_source_infrastructure: CandidateSourceIP
    metadata: RelayAnalysisMetadata


class EmailAnalysisResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: str | None = Field(alias="from")
    to: str | None
    cc: str | None
    bcc: str | None
    subject: str | None
    date: str | None
    message_id: str | None
    reply_to: str | None
    return_path: str | None
    mime_version: str | None
    content_type: str | None
    received: list[str]
    body_text: str | None
    body_html: str | None
    attachments: list[AttachmentMetadata]
    relay_analysis: RelayAnalysis | None = None
    security_analysis: SecurityAnalysis | None = None
    threat_intelligence: ThreatIntelligence | None = None
    # Step 6 is additive: the parser and Steps 1-5 fields remain unchanged.
    correlations: list[Correlation] = Field(default_factory=list)
    evidence_graph: EvidenceGraph | None = None
    risk_assessment: RiskAssessment | None = None
    confidence: ConfidenceAssessment | None = None
    attribution: AttributionAssessment | None = None
    attribution_limitations: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    investigation_summary: InvestigationSummary | None = None
    investigation: InvestigationAnalysis | None = None
    # Retained on the internal model for security_analysis; it is not a new
    # top-level response field so existing API consumers keep the same shape.
    authentication_results: list[str] = Field(default_factory=list, exclude=True)

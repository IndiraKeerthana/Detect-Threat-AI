"""Step 6 composition service."""

from app.schemas.investigation import InvestigationAnalysis
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence
from app.services.correlation_engine import build_evidence_graph
from app.services.investigation_summary import build_investigation_summary
from app.services.threat_engine import assess_threat
from app.schemas.email import EmailAnalysisResponse


def analyze_investigation(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
) -> InvestigationAnalysis:
    # Email is accepted for orchestration compatibility; only structured
    # analyses are consumed by the Step 6 services.
    del email
    evidence_graph = build_evidence_graph(security_analysis, threat_intelligence)
    risk_assessment, attribution, actions = assess_threat(
        security_analysis, threat_intelligence, evidence_graph
    )
    summary = build_investigation_summary(risk_assessment, attribution, evidence_graph)
    return InvestigationAnalysis(
        correlations=evidence_graph.correlations,
        evidence_graph=evidence_graph,
        risk_assessment=risk_assessment,
        attribution=attribution,
        recommended_actions=actions,
        investigation_summary=summary,
    )

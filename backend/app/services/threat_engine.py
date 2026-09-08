"""Explainable, bounded Step 6 risk and response engine."""

from __future__ import annotations

from app.schemas.investigation import (
    AttributionAssessment,
    ConfidenceAssessment,
    ConfidenceFactor,
    EvidenceGraph,
    RecommendedAction,
    RiskAssessment,
    RiskFactor,
)
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence

_WEIGHTS = {"info": 1, "low": 5, "medium": 12, "high": 22, "critical": 35}
_CATEGORY_CAPS = {
    "authentication": 28,
    "content": 32,
    "url": 28,
    "identity": 20,
    "attachment": 18,
    "intelligence": 30,
}


def assess_threat(
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    evidence_graph: EvidenceGraph,
) -> tuple[RiskAssessment, AttributionAssessment, list[RecommendedAction]]:
    factors: list[RiskFactor] = []
    by_code: dict[str, RiskFactor] = {}
    for indicator in security_analysis.indicators:
        factor = by_code.get(indicator.code)
        if factor is not None:
            factor.evidence = sorted(set(factor.evidence).union(indicator.evidence))
            continue
        factor = RiskFactor(
            code=indicator.code,
            title=indicator.title,
            contribution=_WEIGHTS[indicator.severity],
            severity=indicator.severity,
            explanation=indicator.explanation,
            evidence=list(indicator.evidence),
            source="security_analysis",
            sources=["security_analysis"],
            category=indicator.category,
        )
        by_code[indicator.code] = factor
        factors.append(factor)

    # Provider observations corroborate local indicators.  At most one
    # reputation increment is retained for each observable/kind.
    seen_observations: set[tuple[str, str, str]] = set()
    for observation in threat_intelligence.observations:
        contribution = _observation_contribution(observation)
        key = (observation.entity_type, observation.entity, observation.kind)
        if contribution and key not in seen_observations:
            seen_observations.add(key)
            factors.append(
                RiskFactor(
                    code=f"intel_{observation.entity_type}_{observation.entity}_{observation.kind}",
                    title=f"{observation.provider} {observation.kind}",
                    contribution=contribution,
                    severity="high" if contribution >= 20 else "medium",
                    explanation="A normalized provider observation supports additional review.",
                    evidence=observation.evidence or [observation.entity],
                    source=observation.provider,
                    sources=[observation.provider],
                    category="intelligence",
                )
            )

    classification, threat_types = _classification(factors)
    factors = _apply_category_caps(factors)
    raw_score = sum(item.contribution for item in factors)
    # A collection of merely suspicious indicators must not look like a
    # definitive maximum-risk result. Phishing/BEC combinations retain 100.
    score = min(95 if classification == "suspicious" else 100, raw_score)
    level = _risk_level(score)
    confidence = _confidence(security_analysis, threat_intelligence, factors, evidence_graph)
    assessment = RiskAssessment(
        score=score,
        level=level,
        classification=classification,
        threat_types=threat_types,
        factors=factors,
        rationale=_rationale(level, factors),
        confidence=confidence,
    )
    attribution = _attribution(threat_intelligence, evidence_graph)
    actions = _recommended_actions(level, security_analysis, attribution)
    return assessment, attribution, actions


def _classification(factors: list[RiskFactor]) -> tuple[str, list[str]]:
    codes = {item.code for item in factors}
    phishing = bool(
        codes
        & {
            "content_credential_request",
            "account_suspension_or_deactivation",
            "url_ip_literal",
            "url_sender_domain_mismatch",
            "url_not_https",
            "spf_fail",
            "dkim_fail",
            "dmarc_fail",
        }
    )
    bec = bool(
        codes
        & {
            "content_payment_request",
            "content_secrecy_or_impersonation",
            "content_callback_or_contact_change",
            "reply_to_mismatch",
            "return_path_mismatch",
        }
    )
    types = [item for item, present in (("phishing", phishing), ("bec", bec)) if present]
    if len(types) > 1:
        return "mixed", types
    if types:
        return types[0], types
    return ("suspicious" if factors else "benign"), (["suspicious"] if factors else [])


def _apply_category_caps(factors: list[RiskFactor]) -> list[RiskFactor]:
    used: dict[str, int] = {}
    for factor in factors:
        category = factor.category if factor.category in _CATEGORY_CAPS else "intelligence"
        remaining = max(0, _CATEGORY_CAPS[category] - used.get(category, 0))
        factor.contribution = min(factor.contribution, remaining)
        used[category] = used.get(category, 0) + factor.contribution
    return [factor for factor in factors if factor.contribution > 0]


def _observation_contribution(observation: object) -> int:
    data = getattr(observation, "data", {})
    if not isinstance(data, dict):
        return 0
    abuse = data.get("abuseConfidenceScore")
    if isinstance(abuse, (int, float)):
        return 25 if abuse >= 80 else 15 if abuse >= 40 else 0
    stats = data.get("last_analysis_stats")
    if isinstance(stats, dict):
        malicious = stats.get("malicious")
        if isinstance(malicious, int):
            return 25 if malicious >= 5 else 15 if malicious >= 1 else 0
    return 0


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "benign"


def _confidence(
    security_analysis: SecurityAnalysis,
    intelligence: ThreatIntelligence,
    factors: list[RiskFactor],
    graph: EvidenceGraph,
) -> ConfidenceAssessment:
    limitations: list[str] = []
    errors = [item for item in intelligence.provider_status if item.status == "error"]
    degraded = [item for item in intelligence.provider_status if item.status == "degraded"]
    skipped = [item for item in intelligence.provider_status if item.status == "skipped"]
    if errors:
        limitations.append("One or more threat-intelligence providers failed; coverage is incomplete.")
    if degraded:
        limitations.append("One or more threat-intelligence providers returned partial results; confidence is limited.")
    if skipped:
        limitations.append("Some threat-intelligence providers were not configured.")
    evidence_count = sum(bool(item.evidence) for item in factors)
    local_evidence = bool(
        security_analysis.indicators
        or security_analysis.authentication_results.results
    )
    infrastructure = {
        (node.type, node.value.lower().rstrip("."))
        for node in graph.nodes
        if node.type in {"ip", "domain"}
    }
    meaningful_observations = [
        item
        for item in intelligence.observations
        if item.status == "success"
        and item.entity_type in {"ip", "domain"}
        and item.provider != "local_ip_classification"
        and (item.data or item.evidence)
        and (item.entity_type, item.entity.lower().rstrip(".")) in infrastructure
    ]
    provider_names = {item.provider for item in meaningful_observations}
    uncertain_observations = any(
        item.confidence in {"low", "none"} for item in meaningful_observations
    )
    provider_sources = {
        source
        for correlation in graph.correlations
        for source in correlation.sources
        if source not in {
            "security_analysis",
            "authentication",
            "content_signals",
            "url_extractor",
            "local_correlation",
            "structured_intelligence",
        }
    }
    strong_correlations = sum(
        1
        for correlation in graph.correlations
        if correlation.confidence == "high"
        and provider_sources.intersection(correlation.sources)
    )
    provider_infrastructure = bool(meaningful_observations)
    strong_correlation_consistency = bool(
        strong_correlations >= 2
        and any(node.type in {"ip", "domain"} for node in graph.nodes)
    )
    independently_corroborated = bool(
        (
            provider_infrastructure
            and (
                (local_evidence and not uncertain_observations)
                or len(provider_names) >= 2
                or strong_correlations >= 2
            )
        )
        or (
            strong_correlation_consistency
            and local_evidence
            and not uncertain_observations
        )
    )
    if errors or (factors and evidence_count < len(factors)):
        level = "low"
    elif degraded:
        level = "medium"
    elif uncertain_observations:
        level = "medium"
    elif independently_corroborated and not errors and not degraded and not skipped:
        level = "high"
    elif meaningful_observations or local_evidence or graph.correlations:
        level = "medium"
    else:
        level = "medium"
    return ConfidenceAssessment(
        level=level,
        explanation="Confidence reflects evidence quality and coverage, not the risk score.",
        evidence_count=evidence_count,
        limitations=limitations,
        factors=_confidence_factors(security_analysis, intelligence, graph),
    )


def _confidence_factors(
    security: SecurityAnalysis,
    intelligence: ThreatIntelligence,
    graph: EvidenceGraph,
) -> list[ConfidenceFactor]:
    auth = security.authentication_results
    observations = intelligence.observations
    definitions = [
        ("authentication", [f"{i.method}={i.result}" for i in auth.results],
         ["authentication"] if auth.results else [],
         "Parsed SPF, DKIM, and DMARC results provide authentication coverage."),
        ("content", [i.code for i in security.content_signals.signals],
         ["content_signals"] if security.content_signals.signals else [],
         "Normalized content signals provide explainable content coverage."),
        ("url", [i.normalized_url for i in security.url_analysis.urls],
         sorted({i.source for i in security.url_analysis.urls}),
         "Normalized URLs and metadata provide URL coverage."),
        ("infrastructure", [i.value for i in intelligence.entities if i.type in {"ip", "domain"}],
         sorted({s for i in intelligence.entities for s in i.sources}),
         "Observable domains and IPs provide infrastructure coverage."),
        ("reputation", [i.entity for i in observations if i.kind == "reputation"],
         sorted({i.provider for i in observations if i.kind == "reputation"}),
         "Provider reputation observations provide reputation coverage."),
        ("registration/DNS", [i.entity for i in observations if i.kind in {"registration", "dns", "registration_dns"}],
         sorted({i.provider for i in observations if i.kind in {"registration", "dns", "registration_dns"}}),
         "Provider registration and DNS observations provide registration coverage."),
        ("correlation", [i.code for i in graph.correlations],
         sorted({s for i in graph.correlations for s in i.sources}),
         "Deduplicated structured relationships provide correlation coverage."),
    ]
    result: list[ConfidenceFactor] = []
    for category, evidence, sources, explanation in definitions:
        if not evidence:
            factor_level = "unknown"
        elif category in {"authentication", "content", "url"}:
            factor_level = "medium"
        elif category in {"reputation", "registration/DNS"}:
            relevant = [i for i in observations if i.kind in {"reputation", "registration", "dns", "registration_dns"}]
            factor_level = "high" if any(i.confidence == "high" for i in relevant) else "medium"
        else:
            factor_level = "medium"
        result.append(ConfidenceFactor(
            category=category,
            level=factor_level,
            explanation=explanation,
            evidence_count=len(evidence),
            evidence=sorted(set(evidence))[:30],
            sources=sources,
        ))
    return result


def _rationale(level: str, factors: list[RiskFactor]) -> str:
    if not factors:
        return "No evidence-backed risk factors were detected by the local analysis."
    names = ", ".join(item.code for item in factors[:4])
    suffix = " Additional factors were bounded by category and score limits." if len(factors) > 4 else ""
    return f"{level.title()} risk is supported by: {names}.{suffix}"


def _attribution(intelligence: ThreatIntelligence, graph: EvidenceGraph) -> AttributionAssessment:
    infrastructure = [node.value for node in graph.nodes if node.type in {"ip", "domain", "url"}]
    limitations = [
        "Observable infrastructure does not establish the identity of an actor, operator, or organization.",
        "Relay headers and provider records can be incomplete, spoofed, stale, or shared.",
    ]
    failed = [item.provider for item in intelligence.provider_status if item.status == "error"]
    if failed:
        limitations.append("Attribution coverage is further limited by provider failures: " + ", ".join(sorted(failed)) + ".")
    if not infrastructure:
        return AttributionAssessment(
            status="not_attributed", assessment="No attributable infrastructure observable was available.",
            confidence="unknown", limitations=limitations,
        )
    return AttributionAssessment(
        status="infrastructure_only",
        assessment="Evidence links observables to infrastructure only; it does not attribute an actor.",
        confidence="medium" if not failed else "low",
        supporting_evidence=infrastructure[:20],
        limitations=limitations,
    )


def _recommended_actions(
    level: str,
    security: SecurityAnalysis,
    attribution: AttributionAssessment,
) -> list[RecommendedAction]:
    actions: list[RecommendedAction] = []
    codes = {item.code for item in security.indicators}
    phishing_codes = {
        "content_credential_request", "account_suspension_or_deactivation",
        "url_ip_literal", "url_sender_domain_mismatch", "url_not_https",
    }
    if level in {"high", "critical"} or phishing_codes & codes:
        actions.append(RecommendedAction(
            code="contain_message", priority="urgent",
            action="Quarantine or hold the message and verify the request out of band.",
            rationale="The bounded risk assessment is high or critical.",
            evidence=sorted(codes), title="Contain and verify the message",
            reason="High-severity structured indicators require independent verification.",
            source="risk_assessment",
        ))
    elif level == "medium":
        actions.append(RecommendedAction(
            code="verify_before_action", priority="recommended",
            action="Verify the sender and any payment or credential request using a trusted channel.",
            rationale="Multiple structured indicators warrant review before acting.",
            evidence=sorted(codes), title="Verify before taking action",
            reason="Structured indicators are present but do not establish a definitive threat.",
            source="risk_assessment",
        ))
    else:
        actions.append(RecommendedAction(
            code="continue_monitoring", priority="routine",
            action="No immediate containment is indicated; retain normal monitoring and user reporting.",
            rationale="No material risk factor was identified by the bounded local analysis.",
            evidence=[], title="Continue monitoring",
            reason="No material evidence-backed risk factor was identified.",
            source="security_analysis",
        ))
    identity_codes = {"reply_to_mismatch", "return_path_mismatch", "url_sender_domain_mismatch"}
    if identity_codes & codes:
        actions.append(RecommendedAction(
            code="inspect_identity_alignment", priority="recommended",
            action="Confirm From, Reply-To, Return-Path, and linked domains before trusting the message.",
            rationale="Identity or sender-domain alignment evidence is inconsistent.",
            evidence=sorted(codes & identity_codes), title="Inspect identity alignment",
            reason="Sender identity fields or linked domains are inconsistent.",
            source="security_analysis",
        ))
    if attribution.status != "not_attributed":
        actions.append(RecommendedAction(
            code="do_not_treat_as_attribution", priority="routine",
            action="Treat infrastructure links as investigative leads, not proof of actor identity.",
            rationale="Attribution is intentionally limited to observable infrastructure.",
            evidence=attribution.supporting_evidence[:5],
            title="Do not treat infrastructure as attribution",
            reason="Infrastructure links are investigative leads, not proof of actor identity.",
            source="correlation",
        ))
    _add_evidence_actions(actions, security)
    return actions


def _add_evidence_actions(actions: list[RecommendedAction], security: SecurityAnalysis) -> None:
    codes = {item.code for item in security.indicators}
    auth_codes = {"spf_fail", "dkim_fail", "dmarc_fail"}
    if auth_codes & codes:
        actions.append(RecommendedAction(
            code="verify_authentication", priority="recommended",
            action="Validate authentication results with the sending domain administrator.",
            rationale="One or more authentication methods failed.",
            title="Validate authentication results",
            reason="SPF, DKIM, or DMARC evidence is inconsistent or failed.",
            evidence=sorted(codes & auth_codes), source="authentication",
        ))
    if "suspicious_attachment_type" in codes:
        actions.append(RecommendedAction(
            code="hold_attachment", priority="urgent",
            action="Do not open or execute the attachment; submit it to approved scanning.",
            rationale="Attachment metadata indicates a potentially executable type.",
            title="Hold suspicious attachment",
            reason="Attachment metadata identifies a potentially executable file type.",
            evidence=["suspicious_attachment_type"], source="attachment_metadata",
        ))
    content_codes = sorted(i.code for i in security.indicators if i.code.startswith("content_"))
    if content_codes:
        actions.append(RecommendedAction(
            code="verify_content_request", priority="recommended",
            action="Confirm payment, credential, or secrecy requests through a trusted channel.",
            rationale="Normalized content signals identify a potentially manipulative request.",
            title="Verify the request out of band",
            reason="Content evidence indicates urgency, credential, payment, or secrecy language.",
            evidence=content_codes, source="content_signals",
        ))

    def evidence_for(indicator_codes: set[str]) -> list[str]:
        return sorted({
            evidence
            for indicator in security.indicators
            if indicator.code in indicator_codes
            for evidence in indicator.evidence
            if evidence
        })

    suspicious_url_codes = {
        "url_ip_literal",
        "url_punycode",
        "url_sender_domain_mismatch",
        "url_not_https",
        "excessive_urls",
    }
    suspicious_url_evidence = evidence_for(suspicious_url_codes)
    if suspicious_url_evidence:
        actions.append(RecommendedAction(
            code="investigate_suspicious_url",
            priority="urgent",
            action="Do not open the link; investigate the destination in a safe environment and verify it through a trusted channel.",
            rationale="URL evidence indicates that a linked destination requires investigation before it is trusted.",
            title="Investigate suspicious URL",
            reason="A suspicious URL indicator is supported by extracted message evidence.",
            evidence=suspicious_url_evidence,
            source="url_analysis",
        ))

    financial_evidence = evidence_for({"content_payment_request"})
    if financial_evidence:
        actions.append(RecommendedAction(
            code="verify_financial_request",
            priority="urgent",
            action="Verify financial requests and payment-detail changes with the sender using a known, independent contact method.",
            rationale="Payment or financial-request evidence should be independently verified before any transfer or change.",
            title="Verify financial request",
            reason="Content evidence indicates a financial or payment request.",
            evidence=financial_evidence,
            source="content_signals",
        ))

    credential_evidence = evidence_for({
        "content_credential_request",
        "account_suspension_or_deactivation",
    })
    if credential_evidence:
        actions.append(RecommendedAction(
            code="secure_credentials",
            priority="urgent",
            action="Do not enter credentials; change exposed passwords and enable multi-factor authentication through the trusted service.",
            rationale="Credential or account-verification evidence may indicate an attempt to capture account access.",
            title="Secure credentials",
            reason="Content evidence requests credentials or pressures the recipient to verify an account.",
            evidence=credential_evidence,
            source="content_signals",
        ))


assess_risk = assess_threat

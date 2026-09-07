"""Bounded Step 7 agent orchestration and context reduction."""

from __future__ import annotations

import logging
from typing import Any

from app.config import Settings, get_settings
from app.schemas.email import EmailAnalysisResponse
from app.schemas.investigation import InvestigationAnalysis
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence
from app.services.ai_agent.provider import (
    LLMProvider,
    ProviderDecision,
    ProviderError,
    create_provider,
)
from app.services.ai_agent.schemas import AIAttribution, AIFinding, AIInvestigationResult, AIToolCall
from app.services.ai_agent.tools import ToolRegistry, ToolValidationError, make_tool_registry, tool_call_key

logger = logging.getLogger(__name__)
_SECRET_KEYS = {"secret", "token", "password", "authorization", "api_key", "apikey", "raw", "body", "attachment"}


def _safe_value(value: Any, depth: int = 0) -> Any:
    """Bound provider context and remove common credential/raw-content keys."""
    if depth > 3:
        return None
    if isinstance(value, dict):
        return {
            str(key): _safe_value(item, depth + 1)
            for key, item in value.items()
            if str(key).lower() not in _SECRET_KEYS
        }
    if isinstance(value, list):
        return [_safe_value(item, depth + 1) for item in value[:50]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if not isinstance(value, str) else value[:500]
    return str(value)[:200]


def build_investigation_context(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    investigation: InvestigationAnalysis,
) -> dict[str, Any]:
    """Build a bounded context from parsed, Step 5, and Step 6 models only."""
    del email  # The route passes the parsed model for API symmetry; no raw body is used.
    entities: list[dict[str, Any]] = []

    def add_entity(entity_type: str, value: str | None, sources: list[str] | None = None) -> None:
        if not value:
            return
        item = {"type": entity_type, "value": value, "sources": sources or []}
        if not any(
            existing["type"] == entity_type and existing["value"].lower() == value.lower()
            for existing in entities
        ):
            entities.append(item)

    for entity in threat_intelligence.entities:
        add_entity(entity.type, entity.value, entity.sources)
    for item in security_analysis.url_analysis.urls:
        add_entity("url", item.normalized_url, [item.source])
        add_entity("domain", item.domain, [item.source])
    for item in security_analysis.url_analysis.domains:
        add_entity("domain", item.domain, [item.source])
    for item in security_analysis.domains:
        add_entity("domain", item.domain, [item.source])
    if security_analysis.authentication_results.from_domain:
        add_entity("domain", security_analysis.authentication_results.from_domain, ["authentication"])
    relay = getattr(investigation, "evidence_graph", None)
    if relay:
        for node in relay.nodes:
            if node.type in {"ip", "domain", "url"}:
                add_entity(node.type, node.value, node.sources)

    observations = []
    for item in threat_intelligence.observations:
        observations.append(
            _safe_value(
                {
                    "provider": item.provider,
                    "entity_type": item.entity_type,
                    "entity": item.entity,
                    "kind": item.kind,
                    "status": item.status,
                    "data": item.data,
                    "evidence": item.evidence,
                    "confidence": item.confidence,
                }
            )
        )
    compact = {
        "risk_level": investigation.risk_assessment.level,
        "classification": investigation.risk_assessment.classification,
        "confidence": investigation.risk_assessment.confidence.level,
        "risk_factors": [
            {
                "code": item.code,
                "title": item.title,
                "severity": item.severity,
                "evidence": item.evidence[:2],
            }
            for item in investigation.risk_assessment.factors[:8]
        ],
        "confidence_factors": [
            {
                "category": item.category,
                "level": item.level,
                "evidence": item.evidence[:2],
            }
            for item in investigation.risk_assessment.confidence.factors
        ],
        "sender_from_domain": security_analysis.authentication_results.from_domain,
        "reply_to_domain": security_analysis.authentication_results.reply_to_domain,
        "return_path_domain": security_analysis.authentication_results.return_path_domain,
        "probable_source_ip": next(
            (
                node.value
                for node in investigation.evidence_graph.nodes
                if node.type == "ip" and node.properties.get("probable_source") is True
            ),
            None,
        ),
        "key_urls": [item.normalized_url for item in security_analysis.url_analysis.urls[:8]],
        "authentication": _safe_value(
            {
                "spf": security_analysis.authentication_results.spf.model_dump()
                if security_analysis.authentication_results.spf
                else None,
                "dkim": security_analysis.authentication_results.dkim.model_dump()
                if security_analysis.authentication_results.dkim
                else None,
                "dmarc": security_analysis.authentication_results.dmarc.model_dump()
                if security_analysis.authentication_results.dmarc
                else None,
            }
        ),
        "provider_findings": [
            _safe_value(
                {
                    "provider": item.provider,
                    "entity_type": item.entity_type,
                    "entity": item.entity,
                    "kind": item.kind,
                    "status": item.status,
                    "data": item.data,
                    "evidence": item.evidence[:2],
                    "confidence": item.confidence,
                }
            )
            for item in threat_intelligence.observations[:12]
        ],
        "correlations": _safe_value(
            [
                {
                    "code": item.code,
                    "relationship": item.relationship,
                    "explanation": item.explanation,
                    "evidence": item.evidence[:2],
                    "entities": item.entities[:6],
                }
                for item in investigation.correlations[:8]
            ]
        ),
    }
    return {
        "compact": compact,
        "entities": entities[:100],
        "indicators": _safe_value([item.model_dump() for item in security_analysis.indicators]),
        "content_signals": _safe_value([item.model_dump() for item in security_analysis.content_signals.signals]),
        "authentication": _safe_value(
            {
                "spf": security_analysis.authentication_results.spf.model_dump()
                if security_analysis.authentication_results.spf
                else None,
                "dkim": security_analysis.authentication_results.dkim.model_dump()
                if security_analysis.authentication_results.dkim
                else None,
                "dmarc": security_analysis.authentication_results.dmarc.model_dump()
                if security_analysis.authentication_results.dmarc
                else None,
            }
        ),
        "observations": observations[:100],
        "relationships": _safe_value([item.model_dump() for item in threat_intelligence.relationships]),
        "risk_assessment": _safe_value(investigation.risk_assessment.model_dump()),
        "attribution": _safe_value(investigation.attribution.model_dump()),
        "graph": _safe_value(investigation.evidence_graph.model_dump()),
    }


def _fallback(
    investigation: InvestigationAnalysis,
    *,
    iterations: int = 0,
    tool_calls: list[AIToolCall] | None = None,
) -> AIInvestigationResult:
    summary = investigation.investigation_summary
    return AIInvestigationResult(
        summary=summary.summary,
        risk_level=summary.risk_level,
        classification=investigation.risk_assessment.classification,
        confidence=summary.confidence,
        reasoning=investigation.risk_assessment.rationale,
        key_findings=[
            AIFinding(
                title=factor.title,
                severity=factor.severity,
                explanation=factor.explanation,
                evidence=factor.evidence[:5],
            )
            for factor in investigation.risk_assessment.factors[:8]
        ],
        recommended_actions=[
            item.action or item.title or item.code for item in investigation.recommended_actions[:8]
        ],
        attribution=AIAttribution(
            status=investigation.attribution.status,
            assessment=investigation.attribution.assessment,
            confidence=investigation.attribution.confidence,
            supporting_evidence=investigation.attribution.supporting_evidence[:8],
            limitations=investigation.attribution.limitations[:8],
        ),
        evidence=[
            evidence
            for edge in investigation.evidence_graph.edges[:12]
            for evidence in edge.evidence[:2]
        ][:20],
        tool_calls=tool_calls or [],
        iterations=min(iterations, 20),
        source="deterministic_fallback",
    )


def deterministic_fallback(
    investigation: InvestigationAnalysis, *, iterations: int = 0
) -> AIInvestigationResult:
    """Public deterministic result constructor used by integrations/tests."""
    return _fallback(investigation, iterations=iterations)


def _coerce_decision(value: Any) -> ProviderDecision:
    if isinstance(value, ProviderDecision):
        return value
    if isinstance(value, dict):
        kind = value.get("kind", value.get("type"))
        if kind in {"tool_call", "tool"}:
            return ProviderDecision(kind=kind, tool=value.get("tool"), arguments=value.get("arguments", {}))
        if kind == "final":
            return ProviderDecision(kind=kind, result=value.get("result", value.get("data")))
    raise ProviderError("malformed provider decision")


class AIInvestigationAgent:
    """Execute provider decisions with strict registry and iteration bounds."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        max_iterations: int = 5,
        registry_factory=make_tool_registry,
    ) -> None:
        self.provider = provider
        self.max_iterations = max(1, min(int(max_iterations), 20))
        self.registry_factory = registry_factory

    def investigate(
        self,
        context: dict[str, Any],
        deterministic: InvestigationAnalysis,
    ) -> AIInvestigationResult:
        registry: ToolRegistry = self.registry_factory(context)
        history: list[dict[str, Any]] = []
        calls: list[AIToolCall] = []
        seen: set[str] = set()
        for iteration in range(1, self.max_iterations + 1):
            try:
                decision = _coerce_decision(
                    self.provider.decide(context, history, registry.names)
                )
                logger.debug("AI investigation iteration %d decision=%s", iteration, decision.kind)
                if decision.kind == "final" and decision.result is not None:
                    result = AIInvestigationResult.model_validate(decision.result)
                    result.iterations = iteration
                    result.source = "ai_agent"
                    self._validate_result(result, context)
                    result.tool_calls = calls
                    return result
                if decision.kind != "tool_call" or not decision.tool or not isinstance(decision.arguments, dict):
                    raise ProviderError("malformed provider decision")
                key = tool_call_key(decision.tool, decision.arguments)
                if key in seen:
                    raise ProviderError("repeated tool call")
                seen.add(key)
                output = registry.execute(decision.tool, decision.arguments)
                summary = f"{decision.tool} returned {len(output)} field(s)."
                calls.append(AIToolCall(name=decision.tool, arguments=decision.arguments, result_summary=summary))
                history.append({"type": "tool_result", "tool": decision.tool, "result": _safe_value(output)})
            except (ProviderError, ToolValidationError, ValueError, TypeError):
                return _fallback(deterministic, iterations=iteration, tool_calls=calls)
        return _fallback(deterministic, iterations=self.max_iterations, tool_calls=calls)

    @staticmethod
    def _validate_result(result: AIInvestigationResult, context: dict[str, Any]) -> None:
        # Provider output cannot broaden attribution beyond infrastructure leads.
        if result.attribution.status != "not_attributed":
            unsafe_terms = ("threat actor", "attacker", "criminal group", "attributed to")
            if any(term in result.attribution.assessment.lower() for term in unsafe_terms):
                result.attribution.assessment = (
                    "Infrastructure indicators are investigative leads; no actor attribution is supported."
                )
                result.attribution.status = "infrastructure_only"
                result.attribution.confidence = "low"
            result.attribution.limitations.append(
                "Infrastructure evidence does not identify or attribute a human actor."
            )
        known = {
            str(item.get("value", "")).lower()
            for item in context.get("entities", [])
            if isinstance(item, dict)
        }
        for evidence in result.evidence:
            lowered = evidence.lower()
            if "http://" in lowered or "https://" in lowered:
                if not any(entity in lowered for entity in known):
                    raise ProviderError("provider supplied unsupported evidence")


def run_ai_investigation(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    investigation: InvestigationAnalysis,
    *,
    settings: Settings | Any | None = None,
    provider: LLMProvider | None = None,
) -> AIInvestigationResult:
    """Run Step 7, failing closed to the deterministic Step 6 result."""
    settings = settings or get_settings()
    enabled = bool(getattr(settings, "ai_agent_enabled", False))
    deterministic = _fallback(investigation)
    if not enabled:
        return deterministic
    try:
        context = build_investigation_context(email, security_analysis, threat_intelligence, investigation)
        selected = provider or create_provider(
            str(getattr(settings, "ai_provider", "openai")),
            api_key=getattr(settings, "ai_api_key", None),
            model=str(getattr(settings, "ai_model", "gpt-4o-mini")),
            timeout_seconds=float(getattr(settings, "ai_agent_timeout_seconds", 30.0)),
        )
        return AIInvestigationAgent(
            selected,
            max_iterations=int(getattr(settings, "ai_agent_max_iterations", 5)),
        ).investigate(context, investigation)
    except Exception as exc:
        # Never expose provider URLs, response bodies, keys, or exception text.
        logger.warning("AI investigation unavailable (%s)", type(exc).__name__)
        return deterministic


# Concise compatibility entry points for callers that do not need the class.
investigate = run_ai_investigation
build_context = build_investigation_context

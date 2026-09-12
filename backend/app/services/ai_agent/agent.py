"""Bounded Step 7 agent orchestration and context reduction."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.config import Settings, get_settings
from app.schemas.email import EmailAnalysisResponse
from app.schemas.investigation import InvestigationAnalysis
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence
from app.services.ai_agent.prompts import (
    FINAL_SYNTHESIS_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    make_initial_user_prompt,
)
from app.services.ai_agent.provider import (
    LLMProvider,
    ProviderDecision,
    ProviderError,
    _clean_and_parse_json,
    create_provider,
)
from app.services.ai_agent.schemas import AIAttribution, AIFinding, AIInvestigationResult, AIToolCall
from app.services.ai_agent.tools import ToolRegistry, ToolValidationError, make_tool_registry, tool_call_key

logger = logging.getLogger(__name__)


class AIConfigurationError(RuntimeError):
    """Raised when AI agent is disabled or required configuration/key is missing."""


class AIAnalysisError(RuntimeError):
    """Raised when AI provider request, execution, or validation fails."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "provider failure",
        status_code: int | None = None,
        iteration: int = 0,
        provider: str | None = None,
        model: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.status_code = status_code
        self.iteration = iteration
        self.provider = provider
        self.model = model


_SECRET_KEYS = {"secret", "token", "password", "authorization", "api_key", "apikey", "raw", "body", "attachment"}
CONSERVATIVE_ATTRIBUTION = (
    "The evidence supports identification of suspicious infrastructure, but does not establish "
    "the attacker's identity, sophistication, affiliation, or intent beyond the observed indicators."
)
FOUNDATION_SYSTEM_PROMPT = """You are a bounded email-forensics assistant.
Use only the supplied structured evidence. Do not invent facts, entities, URLs,
actors, or provider observations. Do not claim human attribution; use
infrastructure_only. Return exactly one JSON object matching this schema:
{
  "summary": "concise summary string",
  "risk_level": "low or medium or high or critical",
  "classification": "benign or suspicious or phishing or malware or spoofing or bec or spam",
  "confidence": "low or medium or high",
  "reasoning": "evidence-backed rationale string",
  "key_findings": [
    {"title": "string", "severity": "info or low or medium or high or critical", "explanation": "string", "evidence": ["string"]}
  ],
  "recommended_actions": ["string"],
  "attribution": {
    "status": "infrastructure_only",
    "assessment": "string",
    "confidence": "low or medium or high or unknown",
    "supporting_evidence": ["string"],
    "limitations": ["string"]
  },
  "evidence": ["string"],
  "tool_calls": [],
  "iterations": 1,
  "source": "ai_agent"
}
Keep the response concise and evidence-backed. Set source to ai_agent and
iterations to 1. Do not include chain-of-thought."""


def _safe_value(value: Any, depth: int = 0, max_str_len: int = 500) -> Any:
    """Bound provider context and remove common credential/raw-content keys."""
    if depth > 4:
        return None
    if isinstance(value, dict):
        return {
            str(key): _safe_value(item, depth + 1, max_str_len)
            for key, item in value.items()
            if str(key).lower() not in _SECRET_KEYS
        }
    if isinstance(value, list):
        return [_safe_value(item, depth + 1, max_str_len) for item in value[:50]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if not isinstance(value, str) else value[:max_str_len]
    return str(value)[:200]


def build_investigation_context(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    investigation: InvestigationAnalysis,
) -> dict[str, Any]:
    body_text = getattr(email, "body_text", None) or ""
    body_html = getattr(email, "body_html", None) or ""

    extracted_html_text = ""
    if body_html:
        extracted_html_text = re.sub(r"<[^>]+>", " ", body_html)
        extracted_html_text = re.sub(r"\s+", " ", extracted_html_text).strip()

    email_content = {
        "subject": getattr(email, "subject", None),
        "from": getattr(email, "from_", None),
        "to": getattr(email, "to", None),
        "cc": getattr(email, "cc", None),
        "reply_to": getattr(email, "reply_to", None),
        "return_path": getattr(email, "return_path", None),
        "date": getattr(email, "date", None),
        "message_id": getattr(email, "message_id", None),
        "body_preview": (body_text or extracted_html_text or "")[:5000] if (body_text or extracted_html_text) else None,
        "html_preview": extracted_html_text[:5000] if extracted_html_text else None,
        "attachment_files": [
            {
                "filename": getattr(a, "filename", None),
                "content_type": getattr(a, "content_type", ""),
                "size": getattr(a, "size", 0),
            }
            for a in (getattr(email, "attachments", None) or [])
        ],
    }
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

    # Register email headers and observables into entities
    from_val = getattr(email, "from_", None)
    if from_val:
        add_entity("email", from_val, ["from_header"])
    reply_to_val = getattr(email, "reply_to", None)
    if reply_to_val:
        add_entity("email", reply_to_val, ["reply_to_header"])
    return_path_val = getattr(email, "return_path", None)
    if return_path_val:
        add_entity("email", return_path_val, ["return_path_header"])

    for entity in threat_intelligence.entities:
        add_entity(entity.type, entity.value, entity.sources)
    for item in security_analysis.url_analysis.urls:
        add_entity("url", item.normalized_url, [item.source])
        add_entity("url", item.url, [item.source])
        add_entity("domain", item.domain, [item.source])
    for item in security_analysis.url_analysis.domains:
        add_entity("domain", item.domain, [item.source])
    for item in security_analysis.domains:
        add_entity("domain", item.domain, [item.source])
    if security_analysis.authentication_results.from_domain:
        add_entity("domain", security_analysis.authentication_results.from_domain, ["authentication"])
    if security_analysis.authentication_results.reply_to_domain:
        add_entity("domain", security_analysis.authentication_results.reply_to_domain, ["authentication"])
    if security_analysis.authentication_results.return_path_domain:
        add_entity("domain", security_analysis.authentication_results.return_path_domain, ["authentication"])
    relay = getattr(investigation, "evidence_graph", None)
    if relay:
        for node in relay.nodes:
            if node.type in {"ip", "domain", "url", "email"}:
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
        "email_content": email_content,
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
        "extracted_urls": [
            {
                "url": item.url,
                "normalized_url": item.normalized_url,
                "domain": item.domain,
                "scheme": item.scheme,
                "source": item.source,
            }
            for item in security_analysis.url_analysis.urls[:10]
        ],
        "key_urls": [item.normalized_url for item in security_analysis.url_analysis.urls[:8]],
        "authentication": _safe_value(
            {
                "from_domain": security_analysis.authentication_results.from_domain,
                "reply_to_domain": security_analysis.authentication_results.reply_to_domain,
                "return_path_domain": security_analysis.authentication_results.return_path_domain,
                "spf": security_analysis.authentication_results.spf.model_dump()
                if security_analysis.authentication_results.spf
                else None,
                "dkim": security_analysis.authentication_results.dkim.model_dump()
                if security_analysis.authentication_results.dkim
                else None,
                "dmarc": security_analysis.authentication_results.dmarc.model_dump()
                if security_analysis.authentication_results.dmarc
                else None,
                "alignment_notes": security_analysis.authentication_results.alignment_notes,
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

    try:
        from app.services.case_storage import find_historical_matches
        src_ip = next(
            (
                node.value
                for node in investigation.evidence_graph.nodes
                if node.type == "ip" and node.properties.get("probable_source") is True
            ),
            None,
        )
        url_vals = [item.normalized_url for item in security_analysis.url_analysis.urls]
        dom_vals = [item.domain for item in security_analysis.url_analysis.domains]
        att_hashes = [
            getattr(a, "sha256", None)
            for a in (getattr(email, "attachments", None) or [])
            if getattr(a, "sha256", None)
        ]

        hist_matches = find_historical_matches(
            email_from=getattr(email, "from_", None),
            source_ip=src_ip,
            urls=url_vals,
            domains=dom_vals,
            attachment_hashes=att_hashes,
            limit=5,
        )
    except Exception:
        hist_matches = []

    compact["historical_cases"] = _safe_value(hist_matches)

    return {
        "compact": compact,
        "entities": entities[:100],
        "historical_cases": _safe_value(hist_matches),
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


def build_foundation_context(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    investigation: InvestigationAnalysis,
) -> dict[str, Any]:
    """Build the small, one-request context used to prove real AI integration."""
    auth = security_analysis.authentication_results
    source_ip = (
        email.relay_analysis.probable_source_infrastructure.address
        if email.relay_analysis
        else None
    )
    observations = sorted(
        threat_intelligence.observations,
        key=lambda item: (item.status != "success", item.confidence != "high"),
    )[:5]
    return {
        "risk_level": investigation.risk_assessment.level,
        "classification": investigation.risk_assessment.classification,
        "confidence": investigation.risk_assessment.confidence.level,
        "risk_factors": [
            {
                "code": item.code,
                "severity": item.severity,
                "evidence": item.evidence[:2],
            }
            for item in investigation.risk_assessment.factors[:5]
        ],
        "authentication": {
            "spf": auth.spf.result if auth.spf else None,
            "dkim": auth.dkim.result if auth.dkim else None,
            "dmarc": auth.dmarc.result if auth.dmarc else None,
        },
        "from_domain": auth.from_domain,
        "reply_to_domain": auth.reply_to_domain,
        "return_path_domain": auth.return_path_domain,
        "probable_source_ip": source_ip,
        "urls": [item.normalized_url for item in security_analysis.url_analysis.urls[:3]],
        "threat_intelligence": [
            {
                "provider": item.provider,
                "entity": item.entity,
                "kind": item.kind,
                "status": item.status,
                "evidence": item.evidence[:2],
            }
            for item in observations
        ],
        "correlations": [
            {
                "code": item.code,
                "relationship": item.relationship,
                "entities": item.entities[:4],
                "evidence": item.evidence[:2],
            }
            for item in investigation.correlations[:5]
        ],
    }


def run_foundation_ai_investigation(
    email: EmailAnalysisResponse,
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
    investigation: InvestigationAnalysis,
    *,
    settings: Settings | Any | None = None,
) -> AIInvestigationResult:
    """Run exactly one bounded provider request without deterministic fallback."""
    settings = settings or get_settings()
    if not bool(getattr(settings, "ai_agent_enabled", False)):
        raise AIConfigurationError("AI Analyst is disabled (AI_AGENT_ENABLED=false).")
    api_key = (
        getattr(settings, "effective_ai_api_key", None)
        or getattr(settings, "groq_api_key", None)
        or getattr(settings, "ai_api_key", None)
    )
    if not api_key:
        raise AIConfigurationError("AI Analyst configuration error: Missing required API key.")
    try:
        selected = create_provider(
            str(getattr(settings, "ai_provider", "openai")),
            api_key=api_key,
            model=str(getattr(settings, "ai_model", "gpt-4o-mini")),
            timeout_seconds=float(getattr(settings, "ai_agent_timeout_seconds", 30.0)),
        )
        if not hasattr(selected, "decide_once"):
            raise ProviderError("provider does not support foundation mode")
        decision = selected.decide_once(
            build_foundation_context(email, security_analysis, threat_intelligence, investigation),
            system_prompt=FOUNDATION_SYSTEM_PROMPT,
            max_tokens=700,
        )
        if decision.kind != "final" or decision.result is None:
            raise ProviderError("provider did not return a final investigation")
        result = AIInvestigationResult.model_validate(decision.result)
        result.iterations = 1
        result.source = "ai_agent"
        result.provider = getattr(selected, "name", "openai")
        result.model = getattr(selected, "model", None)
        AIInvestigationAgent._validate_result(result, build_investigation_context(
            email, security_analysis, threat_intelligence, investigation
        ))
        result.tool_calls = []
        return result
    except AIConfigurationError:
        raise
    except Exception as exc:
        logger.warning("AI foundation unavailable (%s)", type(exc).__name__)
        raise AIAnalysisError(f"AI foundation analysis failed: {type(exc).__name__}") from exc


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


def _normalize_final_data(
    final_data: dict[str, Any],
    calls: list[AIToolCall],
    provider: Any,
    iteration: int,
) -> dict[str, Any]:
    data = dict(final_data)
    data["source"] = "ai_agent"
    data["iterations"] = iteration
    data["tool_calls"] = calls
    data["provider"] = getattr(provider, "name", "groq")
    data["model"] = getattr(provider, "model", None)

    # 1. Normalize risk_level / threat_level
    raw_risk = str(data.get("risk_level") or data.get("threat_level") or "medium").lower()
    valid_risk_levels = {"benign", "low", "medium", "high", "critical"}
    if raw_risk in valid_risk_levels:
        data["risk_level"] = raw_risk
    elif raw_risk in {"severe", "urgent", "critical_threat"}:
        data["risk_level"] = "critical"
    elif raw_risk in {"malicious", "phishing", "bec", "elevated"}:
        data["risk_level"] = "high"
    elif raw_risk in {"informational", "clean", "safe"}:
        data["risk_level"] = "benign"
    else:
        data["risk_level"] = "medium"

    # 2. Normalize classification
    raw_class = str(data.get("classification") or "suspicious").lower()
    valid_classifications = {"benign", "phishing", "bec", "mixed", "suspicious", "malware", "spoofing", "spam"}
    if raw_class in valid_classifications:
        data["classification"] = raw_class
    elif "phish" in raw_class:
        data["classification"] = "phishing"
    elif "bec" in raw_class or "wire" in raw_class or "transfer" in raw_class:
        data["classification"] = "bec"
    elif "spoof" in raw_class or "impersonat" in raw_class:
        data["classification"] = "spoofing"
    elif "mal" in raw_class:
        data["classification"] = "malware"
    elif "spam" in raw_class:
        data["classification"] = "spam"
    elif "benign" in raw_class or "clean" in raw_class or "legit" in raw_class:
        data["classification"] = "benign"
    else:
        data["classification"] = "suspicious"

    # 3. Normalize confidence
    raw_conf = str(data.get("confidence") or "medium").lower()
    valid_confidences = {"high", "medium", "low", "unknown"}
    data["confidence"] = raw_conf if raw_conf in valid_confidences else "medium"

    # 4. Summary and reasoning
    if "summary" not in data or not str(data["summary"]).strip():
        raise ProviderError("malformed provider decision: missing summary")
    data["summary"] = str(data["summary"])
    data["reasoning"] = str(data.get("reasoning") or "")

    # 5. Recommended actions / recommendations
    actions_raw = data.get("recommended_actions") or data.get("recommendations") or []
    if isinstance(actions_raw, str):
        data["recommended_actions"] = [actions_raw]
    elif isinstance(actions_raw, list):
        data["recommended_actions"] = [str(x) for x in actions_raw if x]
    else:
        data["recommended_actions"] = []

    # 6. Categorized string lists
    for field in (
        "suspicious_content_findings",
        "authentication_findings",
        "url_findings",
        "attachment_findings",
        "infrastructure_findings",
        "historical_findings",
    ):
        val = data.get(field)
        if isinstance(val, str):
            data[field] = [val]
        elif isinstance(val, list):
            items: list[str] = []
            for item in val:
                if isinstance(item, str):
                    items.append(item)
                elif isinstance(item, dict):
                    title = item.get("title", "Observation")
                    exp = item.get("explanation", item.get("detail", str(item)))
                    items.append(f"{title}: {exp}")
                elif item is not None:
                    items.append(str(item))
            data[field] = items
        else:
            data[field] = []

    # 7. Intent and claimed identity
    if data.get("email_intent") is not None:
        data["email_intent"] = str(data["email_intent"])
    if data.get("claimed_identity") is not None:
        data["claimed_identity"] = str(data["claimed_identity"])
    if data.get("requested_action") is not None:
        data["requested_action"] = str(data["requested_action"])

    # 8. Key findings normalization
    raw_findings = data.get("key_findings") or []
    normalized_findings = []
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if isinstance(f, dict):
                sev = str(f.get("severity", "medium")).lower()
                if sev not in {"info", "low", "medium", "high", "critical"}:
                    sev = "high" if sev in {"urgent", "severe"} else "medium"
                ev = f.get("evidence", [])
                if isinstance(ev, str):
                    ev = [ev]
                elif not isinstance(ev, list):
                    ev = []
                normalized_findings.append({
                    "title": str(f.get("title") or "Observation"),
                    "severity": sev,
                    "explanation": str(f.get("explanation") or f.get("description") or ""),
                    "evidence": [str(e) for e in ev],
                })
            elif isinstance(f, str):
                normalized_findings.append({
                    "title": "Observation",
                    "severity": "medium",
                    "explanation": f,
                    "evidence": [],
                })
    data["key_findings"] = normalized_findings

    # 9. Evidence
    evidence_raw = data.get("evidence")
    if isinstance(evidence_raw, dict):
        data["evidence"] = [
            f"{k}: {v}" if not isinstance(v, (dict, list)) else f"{k}: {json.dumps(v)}"
            for k, v in evidence_raw.items()
        ]
    elif isinstance(evidence_raw, list):
        data["evidence"] = [str(x) for x in evidence_raw]
    else:
        data["evidence"] = []

    # 10. Attribution
    attr_raw = data.get("attribution")
    if isinstance(attr_raw, str):
        data["attribution"] = {
            "status": "infrastructure_only",
            "assessment": attr_raw,
            "confidence": "low",
            "supporting_evidence": [],
            "limitations": ["Infrastructure evidence does not identify or attribute a human actor."],
        }
    elif isinstance(attr_raw, dict):
        status = attr_raw.get("status", "infrastructure_only")
        if status not in {"not_attributed", "infrastructure_only", "limited_attribution"}:
            status = "infrastructure_only"
        conf = str(attr_raw.get("confidence", "low")).lower()
        if conf not in {"high", "medium", "low", "unknown"}:
            conf = "low"
        limits = attr_raw.get("limitations", [])
        if not isinstance(limits, list):
            limits = [str(limits)]
        if not any("identity" in str(item).lower() or "actor" in str(item).lower() for item in limits):
            limits.append("Infrastructure evidence does not identify or attribute a human actor.")
        data["attribution"] = {
            "status": status,
            "assessment": str(attr_raw.get("assessment") or CONSERVATIVE_ATTRIBUTION),
            "confidence": conf,
            "supporting_evidence": [str(e) for e in attr_raw.get("supporting_evidence", [])] if isinstance(attr_raw.get("supporting_evidence"), list) else [],
            "limitations": [str(l) for l in limits],
        }
    else:
        data["attribution"] = {
            "status": "infrastructure_only",
            "assessment": CONSERVATIVE_ATTRIBUTION,
            "confidence": "low",
            "supporting_evidence": [],
            "limitations": ["Infrastructure evidence does not identify or attribute a human actor."],
        }

    # 11. Strictly filter to allowed schema fields for ConfigDict(extra="forbid")
    allowed_keys = {
        "summary",
        "risk_level",
        "classification",
        "confidence",
        "reasoning",
        "key_findings",
        "recommended_actions",
        "attribution",
        "evidence",
        "tool_calls",
        "iterations",
        "source",
        "provider",
        "model",
        "email_intent",
        "claimed_identity",
        "requested_action",
        "suspicious_content_findings",
        "authentication_findings",
        "url_findings",
        "attachment_findings",
        "infrastructure_findings",
        "historical_findings",
    }
    return {k: v for k, v in data.items() if k in allowed_keys}


class AIInvestigationAgent:
    """Execute provider decisions with strict registry and iteration bounds."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        max_iterations: int = 3,
        registry_factory=make_tool_registry,
    ) -> None:
        self.provider = provider
        self.max_iterations = max(1, min(int(max_iterations), 3))
        self.registry_factory = registry_factory

    def investigate(
        self,
        context: dict[str, Any],
        deterministic: InvestigationAnalysis,
    ) -> AIInvestigationResult:
        if hasattr(self.provider, "chat_step"):
            return self._investigate_native(context, deterministic)
        return self._investigate_legacy(context, deterministic)

    def _investigate_native(
        self,
        context: dict[str, Any],
        deterministic: InvestigationAnalysis,
    ) -> AIInvestigationResult:
        from app.services.ai_agent.prompts import (
            FINAL_SYNTHESIS_SYSTEM_PROMPT,
            SYSTEM_PROMPT,
            make_initial_user_prompt,
        )

        registry: ToolRegistry = self.registry_factory(context)
        tools_schema = registry.get_tools_schema()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": make_initial_user_prompt(context)},
        ]
        calls: list[AIToolCall] = []
        seen: set[str] = set()

        for iteration in range(1, self.max_iterations + 1):
            try:
                msg = self.provider.chat_step(messages, tools=tools_schema)
                tool_calls = msg.get("tool_calls")
                if tool_calls and isinstance(tool_calls, list):
                    messages.append({
                        "role": "assistant",
                        "content": msg.get("content"),
                        "tool_calls": tool_calls,
                    })
                    for tc in tool_calls:
                        fn = tc.get("function", {})
                        fn_name = fn.get("name", "")
                        raw_args = fn.get("arguments", "{}")
                        try:
                            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                        except Exception:
                            args = {}
                        if not isinstance(args, dict):
                            args = {}
                        key = tool_call_key(fn_name, args)
                        call_id = tc.get("id", f"call_{len(calls) + 1}")
                        if key in seen:
                            summary = f"Repeated tool call to {fn_name} skipped."
                            calls.append(
                                AIToolCall(
                                    name=fn_name,
                                    arguments=args,
                                    result_summary=summary,
                                    target="",
                                    iteration=iteration,
                                    status="skipped",
                                )
                            )
                            messages.append({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "name": fn_name,
                                "content": json.dumps({"status": "skipped", "message": "Repeated tool call."}),
                            })
                            continue
                        seen.add(key)
                        target = str(
                            args.get("entity")
                            or args.get("ip")
                            or args.get("domain")
                            or args.get("url")
                            or args.get("code")
                            or ""
                        )
                        try:
                            output = registry.execute(fn_name, args)
                            summary = f"{fn_name} returned {len(output)} field(s)."
                            calls.append(
                                AIToolCall(
                                    name=fn_name,
                                    arguments=args,
                                    result_summary=summary,
                                    target=target,
                                    iteration=iteration,
                                    status="success",
                                )
                            )
                            messages.append({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "name": fn_name,
                                "content": json.dumps(_safe_value(output)),
                            })
                        except ToolValidationError as err:
                            summary = f"{fn_name} validation failed: {err}"
                            calls.append(
                                AIToolCall(
                                    name=fn_name,
                                    arguments=args,
                                    result_summary=summary,
                                    target=target,
                                    iteration=iteration,
                                    status="error",
                                )
                            )
                            messages.append({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "name": fn_name,
                                "content": json.dumps({"status": "error", "error": str(err)}),
                            })
                    continue

                if msg.get("content"):
                    messages.append({
                        "role": "assistant",
                        "content": msg.get("content"),
                    })
                break
            except (ProviderError, ValueError, TypeError) as exc:
                logger.warning("AI investigation iteration %d failed (%s)", iteration, type(exc).__name__)
                category = getattr(exc, "category", "provider failure")
                status_code = getattr(exc, "status_code", None)
                model = getattr(self.provider, "model", None)
                provider = getattr(self.provider, "name", "groq")
                raise AIAnalysisError(
                    f"AI investigation iteration {iteration} failed: {type(exc).__name__}",
                    category=category,
                    status_code=status_code,
                    iteration=iteration,
                    provider=provider,
                    model=model,
                ) from exc

        final_data = None
        last_content = messages[-1].get("content") if messages and messages[-1].get("role") == "assistant" else None
        if last_content and isinstance(last_content, str):
            try:
                candidate = _clean_and_parse_json(last_content)
                if isinstance(candidate, dict):
                    inner = candidate.get("result", candidate.get("data", candidate))
                    if isinstance(inner, dict) and ("summary" in inner or "risk_level" in inner):
                        final_data = inner
            except Exception:
                final_data = None

        if final_data is None:
            try:
                final_raw = self.provider.synthesize_final(messages, system_prompt=FINAL_SYNTHESIS_SYSTEM_PROMPT)
                final_data = final_raw.get("result", final_raw.get("data", final_raw))
                if not isinstance(final_data, dict):
                    raise ProviderError("malformed final synthesis response")
            except Exception as exc:
                logger.warning("AI final report synthesis failed (%s)", type(exc).__name__)
                category = getattr(exc, "category", "provider failure")
                status_code = getattr(exc, "status_code", None)
                model = getattr(self.provider, "model", None)
                provider = getattr(self.provider, "name", "groq")
                raise AIAnalysisError(
                    f"AI final report synthesis failed: {type(exc).__name__}",
                    category=category,
                    status_code=status_code,
                    iteration=len(calls) + 1,
                    provider=provider,
                    model=model,
                ) from exc

        try:
            normalized = _normalize_final_data(final_data, calls, self.provider, max(1, len(calls) + 1))
            result = AIInvestigationResult.model_validate(normalized)
            self._validate_result(result, context)
            result.tool_calls = calls
            return result
        except Exception as exc:
            logger.warning("AI final report processing failed (%s)", type(exc).__name__)
            raise AIAnalysisError(f"AI final report processing failed: {type(exc).__name__}") from exc

    def _investigate_legacy(
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
                    if not calls and iteration == 1 and self.max_iterations > 1:
                        history.append({
                            "type": "tool_result",
                            "tool": "investigation_policy",
                            "result": {
                                "status": "investigation_required",
                                "message": (
                                    "Investigation policy requirement: You must execute at least one forensic tool "
                                    "(such as inspect_url, inspect_ip, inspect_domain, or inspect_reputation) "
                                    "to investigate suspicious observables before providing the final report."
                                ),
                            },
                        })
                        continue
                    normalized = _normalize_final_data(dict(decision.result), calls, self.provider, iteration)
                    result = AIInvestigationResult.model_validate(normalized)
                    self._validate_result(result, context)
                    result.tool_calls = calls
                    return result
                if decision.kind != "tool_call" or not decision.tool or not isinstance(decision.arguments, dict):
                    raise ProviderError("malformed provider decision")
                key = tool_call_key(decision.tool, decision.arguments)
                if key in seen:
                    raise ProviderError("repeated tool call")
                seen.add(key)
                target = str(
                    decision.arguments.get("entity")
                    or decision.arguments.get("ip")
                    or decision.arguments.get("domain")
                    or decision.arguments.get("url")
                    or decision.arguments.get("code")
                    or ""
                )
                try:
                    output = registry.execute(decision.tool, decision.arguments)
                    summary = f"{decision.tool} returned {len(output)} field(s)."
                    calls.append(
                        AIToolCall(
                            name=decision.tool,
                            arguments=decision.arguments,
                            result_summary=summary,
                            target=target,
                            iteration=iteration,
                            status="success",
                        )
                    )
                    history.append({"type": "tool_result", "tool": decision.tool, "result": _safe_value(output)})
                except ToolValidationError as err:
                    summary = f"{decision.tool} validation failed: {err}"
                    calls.append(
                        AIToolCall(
                            name=decision.tool,
                            arguments=decision.arguments,
                            result_summary=summary,
                            target=target,
                            iteration=iteration,
                            status="error",
                        )
                    )
                    history.append({"type": "tool_result", "tool": decision.tool, "error": str(err)})
            except (ProviderError, ValueError, TypeError) as exc:
                logger.warning("AI investigation iteration %d failed (%s)", iteration, type(exc).__name__)
                category = getattr(exc, "category", "provider failure")
                status_code = getattr(exc, "status_code", None)
                model = getattr(self.provider, "model", None)
                provider = getattr(self.provider, "name", "groq")
                raise AIAnalysisError(
                    f"AI legacy investigation iteration {iteration} failed: {type(exc).__name__}",
                    category=category,
                    status_code=status_code,
                    iteration=iteration,
                    provider=provider,
                    model=model,
                ) from exc
        raise AIAnalysisError(
            "AI legacy investigation exhausted iterations without returning a final assessment.",
            category="provider failure",
            iteration=self.max_iterations,
            provider=getattr(self.provider, "name", "groq"),
            model=getattr(self.provider, "model", None),
        )

    @staticmethod
    def _validate_result(result: AIInvestigationResult, context: dict[str, Any]) -> None:
        # Provider output cannot broaden attribution beyond infrastructure leads.
        if result.attribution.status != "not_attributed":
            assessment_lower = result.attribution.assessment.lower()
            unsupported_terms = (
                "threat actor",
                "attacker",
                "criminal group",
                "attributed to",
                "apt",
                "sophisticat",
                "skill",
                "novice",
                "nation-state",
                "nation state",
                "state-sponsored",
                "gang",
                "syndicate",
                "affiliation",
                "motive",
                "phishing kit",
                "perpetrator",
            )
            has_unsupported_claim = any(term in assessment_lower for term in unsupported_terms)
            if result.attribution.status == "infrastructure_only" or has_unsupported_claim:
                result.attribution.assessment = CONSERVATIVE_ATTRIBUTION
                result.attribution.status = "infrastructure_only"
                result.attribution.confidence = "low"
            if not any("identity" in item.lower() or "actor" in item.lower() for item in result.attribution.limitations):
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
    """Run Step 7 autonomous AI investigation. Real AI is mandatory; deterministic fallback is prohibited."""
    settings = settings or get_settings()
    enabled = bool(getattr(settings, "ai_agent_enabled", False))
    if not enabled:
        logger.warning("AI Analyst is disabled (AI_AGENT_ENABLED=false). Real AI is mandatory.")
        raise AIConfigurationError("AI Analyst is disabled (AI_AGENT_ENABLED=false). Real AI analysis is mandatory.")

    api_key = (
        getattr(settings, "effective_ai_api_key", None)
        or getattr(settings, "groq_api_key", None)
        or getattr(settings, "ai_api_key", None)
    )
    if not api_key and provider is None:
        logger.warning("AI Analyst enabled but required API key (GROQ_API_KEY / AI_API_KEY) is missing.")
        raise AIConfigurationError("AI Analyst configuration error: Missing required API key (GROQ_API_KEY / AI_API_KEY).")

    context = build_investigation_context(email, security_analysis, threat_intelligence, investigation)
    try:
        selected = provider or create_provider(
            str(getattr(settings, "ai_provider", "groq")),
            api_key=api_key,
            model=str(getattr(settings, "ai_model", "openai/gpt-oss-120b")),
            timeout_seconds=float(getattr(settings, "ai_agent_timeout_seconds", 60.0)),
        )
        return AIInvestigationAgent(
            selected,
            max_iterations=int(getattr(settings, "ai_agent_max_iterations", 3)),
        ).investigate(context, investigation)
    except AIConfigurationError:
        raise
    except AIAnalysisError:
        raise
    except ProviderError as exc:
        logger.warning("AI investigation failed (%s)", type(exc).__name__)
        raise AIAnalysisError(
            f"AI investigation provider failed: {type(exc).__name__}",
            category=getattr(exc, "category", "provider failure"),
            status_code=getattr(exc, "status_code", None),
            iteration=0,
            provider=str(getattr(settings, "ai_provider", "groq")),
            model=str(getattr(settings, "ai_model", "openai/gpt-oss-120b")),
        ) from exc
    except Exception as exc:
        # Never expose provider URLs, response bodies, keys, or exception text.
        logger.warning("AI investigation failed (%s)", type(exc).__name__)
        raise AIAnalysisError(
            f"AI investigation execution failed: {type(exc).__name__}",
            category="provider failure",
            iteration=0,
            provider=str(getattr(settings, "ai_provider", "groq")),
            model=str(getattr(settings, "ai_model", "openai/gpt-oss-120b")),
        ) from exc


# Concise compatibility entry points for callers that do not need the class.
investigate = run_ai_investigation
build_context = build_investigation_context

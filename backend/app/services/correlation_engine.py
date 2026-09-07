"""Deterministic correlation of normalized Step 1-5 evidence.

This module intentionally consumes only structured Step 1-5 models.  It never
needs the raw message or attachment bytes, which keeps the graph safe to pass
to a future renderer.
"""

from __future__ import annotations

import json
import re
from typing import Any, cast
from urllib.parse import urlsplit

from app.schemas.investigation import (
    Confidence,
    Correlation,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    GraphNodeType,
)
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import ThreatIntelligence


def build_evidence_graph(
    security_analysis: SecurityAnalysis,
    threat_intelligence: ThreatIntelligence,
) -> EvidenceGraph:
    """Build a bounded graph without parsing or sending message content."""
    nodes: dict[str, EvidenceGraphNode] = {}
    edges: dict[tuple[str, str, str], EvidenceGraphEdge] = {}

    def node(
        node_type: str,
        value: str,
        sources: list[str] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        value = str(value).strip()
        node_id = f"{node_type}:{value.lower()}"
        if node_id not in nodes:
            nodes[node_id] = EvidenceGraphNode(
                id=node_id,
                type=cast(GraphNodeType, node_type),
                value=value,
                sources=sorted(set(sources or [])),
                properties=_safe_properties(properties),
            )
        else:
            nodes[node_id].sources = sorted(set(nodes[node_id].sources).union(sources or []))
            nodes[node_id].properties.update(_safe_properties(properties))
        return node_id

    email_id = node(
        "email",
        "message",
        ["structured_analysis"],
        {"kind": "analyzed_message"},
    )
    for entity in threat_intelligence.entities:
        node(entity.type, entity.value, entity.sources, {"observable": True})

    # Security analysis is itself structured evidence and remains useful when
    # the intelligence layer has no configured providers.
    for extracted in security_analysis.url_analysis.urls:
        url_id = node(
            "url",
            extracted.normalized_url,
            [extracted.source],
            {"scheme": extracted.scheme, "path": extracted.path, "https": extracted.is_https},
        )
        host_id = node(
            "ip" if _looks_like_ip(extracted.domain) else "domain",
            extracted.domain,
            [extracted.source],
        )
        add_edge(
            edges, url_id, host_id, "hosted_by", ["url_extractor"],
            [extracted.normalized_url, extracted.domain], "high",
        )
    for extracted in security_analysis.domains:
        node("domain", extracted.domain, [extracted.source])
    auth = security_analysis.authentication_results
    for domain, source in (
        (auth.from_domain, "from"),
        (auth.return_path_domain, "return_path"),
        (auth.reply_to_domain, "reply_to"),
        (auth.dkim.domain if auth.dkim else None, "dkim"),
        (auth.dmarc.domain if auth.dmarc else None, "dmarc"),
    ):
        if domain:
            identity_id = node(
                "identity",
                f"{source}:{domain}",
                [source],
                {"field": source, "domain": domain},
            )
            domain_id = node("domain", domain, [source], {"identity_field": source})
            add_edge(
                edges, email_id, identity_id, "has_identity", [source], [domain], "high",
                {"field": source},
            )
            add_edge(
                edges, identity_id, domain_id, "uses_domain", [source], [domain], "high",
            )

    for observation in threat_intelligence.observations:
        observation_id = node(
            "provider",
            f"{observation.provider}:{observation.entity_type}:{observation.entity}:{observation.kind}",
            [observation.provider],
            {"kind": observation.kind, "status": observation.status},
        )
        metadata = (
            _provider_metadata(observation)
            if observation.entity_type in {"ip", "domain"}
            else None
        )
        entity_id = node(
            observation.entity_type,
            observation.entity,
            [observation.provider],
            metadata,
        )
        add_edge(
            edges,
            entity_id,
            observation_id,
            "observed_by",
            [observation.provider],
            observation.evidence or [observation.kind],
            _normalize_confidence(observation.confidence),
            {"kind": observation.kind},
        )
        _add_observation_properties(node, add_edge, edges, entity_id, observation)

    for relationship in threat_intelligence.relationships:
        source_id = node(relationship.source_type, relationship.source)
        target_id = node(relationship.target_type, relationship.target)
        add_edge(
            edges,
            source_id,
            target_id,
            relationship.relationship,
            relationship.providers,
            [],
            "high" if relationship.providers else "medium",
        )

    correlations: list[Correlation] = []
    for indicator in security_analysis.indicators:
        indicator_id = node("indicator", indicator.code, ["security_analysis"])
        evidence = list(indicator.evidence) or [indicator.code]
        matches = _indicator_entities(indicator.evidence, threat_intelligence)
        for item in matches:
            add_edge(
                edges,
                indicator_id,
                node(item[0], item[1]),
                "supported_by",
                ["security_analysis"],
                evidence,
                _indicator_confidence(indicator.severity),
            )
        if not matches:
            add_edge(
                edges, indicator_id, email_id, "observed_in", ["security_analysis"],
                evidence or [indicator.code], _indicator_confidence(indicator.severity),
            )
        correlations.append(
        Correlation(
            code=indicator.code,
            relationship="indicator_supported_by_evidence",
            explanation=indicator.explanation,
            evidence=evidence,
            entities=_indicator_entities_as_values(evidence, threat_intelligence) or ["message"],
            confidence=_indicator_confidence(indicator.severity),
            sources=["security_analysis"],
        )
        )

    # Preserve a useful local relation even when a provider is disabled.
    for entity in threat_intelligence.entities:
        if entity.type != "url":
            continue
        try:
            hostname = (urlsplit(entity.value).hostname or "").lower().rstrip(".")
        except ValueError:
            hostname = ""
        if hostname and any(
            item.type == "domain" and item.value == hostname
            for item in threat_intelligence.entities
        ):
            add_edge(
                edges,
                node("url", entity.value),
                node("domain", hostname),
                "hosted_by",
                ["local_correlation"],
                [entity.value, hostname],
                "high",
            )
            correlations.append(
                Correlation(
                    code="url_domain_correlation",
                    relationship="url_hosted_by_domain",
                    explanation="The extracted URL hostname matches a normalized domain observable.",
                    evidence=[entity.value, hostname],
                    entities=[entity.value, hostname],
                    confidence="high",
                    sources=["local_correlation"],
                )
            )

    correlations.extend(_higher_level_correlations(security_analysis, threat_intelligence, edges))
    correlations = _dedupe_correlations(correlations)

    return EvidenceGraph(
        nodes=sorted(nodes.values(), key=lambda item: item.id),
        edges=sorted(edges.values(), key=lambda item: (item.source, item.target, item.relationship)),
        correlations=sorted(correlations, key=lambda item: (item.code, item.relationship)),
    )


def _indicator_entities(
    evidence: list[str], intelligence: ThreatIntelligence
) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for entity in intelligence.entities:
        if any(entity.value in item or item in entity.value for item in evidence):
            matches.append((entity.type, entity.value))
    return matches


def _indicator_entities_as_values(
    evidence: list[str], intelligence: ThreatIntelligence
) -> list[str]:
    return sorted({value for _, value in _indicator_entities(evidence, intelligence)})


def _higher_level_correlations(
    security: SecurityAnalysis,
    intelligence: ThreatIntelligence,
    edges: dict[tuple[str, str, str], EvidenceGraphEdge],
) -> list[Correlation]:
    """Create bounded, explainable relations from independent structured inputs."""
    result: list[Correlation] = []
    entities = {item.value: item for item in intelligence.entities}
    domains = {item.value.lower(): item.value for item in intelligence.entities if item.type == "domain"}
    urls = [item for item in intelligence.entities if item.type == "url"]
    sender = security.authentication_results.from_domain
    reply = security.authentication_results.reply_to_domain
    returned = security.authentication_results.return_path_domain
    dkim = security.authentication_results.dkim.domain if security.authentication_results.dkim else None

    def add(
        code: str,
        relationship: str,
        values: list[str],
        evidence: list[str],
        explanation: str,
        sources: list[str],
        confidence: Confidence = "medium",
    ) -> None:
        if not values or not evidence:
            return
        result.append(
            Correlation(
                code=code,
                relationship=relationship,
                entities=sorted(set(values)),
                evidence=sorted(set(evidence)),
                confidence=confidence,
                sources=sorted(set(sources)),
                explanation=explanation,
            )
        )

    if sender and reply and sender.lower() != reply.lower():
        add(
            "sender_reply_correlation", "sender_reply_mismatch", [sender, reply],
            [sender, reply], "Reply-To uses a different domain from the authenticated sender.",
            ["authentication", "security_analysis"], "high",
        )
    elif sender and reply:
        add(
            "sender_reply_correlation", "sender_reply_aligned", [sender, reply],
            [sender, reply], "Reply-To is aligned with the authenticated sender domain.",
            ["authentication", "security_analysis"], "high",
        )
    if sender and returned and sender.lower() != returned.lower():
        add(
            "sender_return_correlation", "sender_return_mismatch", [sender, returned],
            [sender, returned], "Return-Path uses a different domain from the authenticated sender.",
            ["authentication", "security_analysis"], "high",
        )
    elif sender and returned:
        add(
            "sender_return_correlation", "sender_return_aligned", [sender, returned],
            [sender, returned], "Return-Path is aligned with the authenticated sender domain.",
            ["authentication", "security_analysis"], "high",
        )
    if sender and dkim and sender.lower() != dkim.lower():
        add(
            "sender_dkim_correlation", "sender_dkim_mismatch", [sender, dkim],
            [sender, dkim], "DKIM signing domain is not aligned with the sender domain.",
            ["authentication", "dkim"], "high",
        )
    elif sender and dkim:
        add(
            "sender_dkim_correlation", "sender_dkim_aligned", [sender, dkim],
            [sender, dkim], "DKIM signing domain is aligned with the sender domain.",
            ["authentication", "dkim"], "high",
        )

    ips = [item.value for item in intelligence.entities if item.type == "ip"]
    sender_ips = [
        item.value for item in intelligence.entities
        if item.type == "ip" and {"received", "sender_ip"} & set(item.sources)
    ]
    if sender and sender_ips:
        add(
            "sender_ip_correlation", "sender_domain_observed_from_ip",
            [sender, *sender_ips], [sender, *sender_ips],
            "The sender domain and a relay/source IP are present in the structured message evidence.",
            ["from", "received"], "medium",
        )

    for relationship in intelligence.relationships:
        values = [relationship.source, relationship.target]
        providers = relationship.providers or ["structured_intelligence"]
        if relationship.relationship in {"resolves_to", "hosted_by", "points_to"}:
            add(
                "domain_ip_correlation", relationship.relationship, values, values,
                "Structured DNS or hosting evidence links a domain and an IP.",
                providers, "high" if relationship.providers else "medium",
            )
        elif relationship.relationship == "announced_by":
            add(
                "ip_asn_correlation", relationship.relationship, values, values,
                "Structured routing evidence links an IP to an ASN.", providers, "high",
            )
        elif relationship.relationship == "located_in":
            add(
                "ip_geolocation_correlation", relationship.relationship, values, values,
                "Structured geolocation evidence links an IP to a location.", providers, "medium",
            )

    for observation in intelligence.observations:
        data = observation.data
        if observation.kind == "reputation" and observation.entity_type in {"ip", "domain"}:
            add(
                "ip_reputation_correlation" if observation.entity_type == "ip" else "domain_reputation_correlation",
                "has_reputation_observation", [observation.entity],
                observation.evidence or [observation.entity],
                "A provider supplied a reputation observation for the infrastructure.",
                [observation.provider], observation.confidence if observation.confidence != "none" else "medium",
            )
        if observation.kind in {"registration", "dns", "registration_dns"}:
            add(
                "registration_dns_correlation", "has_registration_or_dns_observation",
                [observation.entity], observation.evidence or [observation.entity],
                "A provider supplied registration or DNS evidence for the observable.",
                [observation.provider], observation.confidence if observation.confidence != "none" else "medium",
            )
        if observation.kind == "geolocation":
            for field in ("asn", "country", "country_code", "region", "city"):
                value = data.get(field)
                if value:
                    add(
                        "ip_asn_correlation" if field == "asn" else "ip_geolocation_correlation",
                        "ip_has_" + field, [observation.entity, str(value)],
                        observation.evidence or [observation.entity, str(value)],
                        "Provider geolocation data links the IP to structured infrastructure context.",
                        [observation.provider], observation.confidence if observation.confidence != "none" else "medium",
                    )
            if data.get("isp") or data.get("organization"):
                provider_value = data.get("isp") or data.get("organization")
                add(
                    "ip_provider_correlation", "ip_served_by_provider",
                    [observation.entity, str(provider_value)],
                    observation.evidence or [observation.entity, str(provider_value)],
                    "Provider data links the IP to a network or hosting provider.",
                    [observation.provider], "medium",
                )

    if security.content_signals.signals and urls:
        url_values = [item.value for item in urls]
        add(
            "content_url_correlation", "content_signal_targets_url",
            ["content", *url_values],
            [signal.code for signal in security.content_signals.signals] + url_values,
            "Content signals and extracted URLs occur in the same structured message evidence.",
            ["content_signals", "url_extractor"], "medium",
        )
    if security.authentication_results.results and (ips or domains):
        add(
            "auth_infrastructure_correlation", "authentication_context_has_infrastructure",
            ["authentication", *(ips or list(domains.values()))],
            [item.method + "=" + item.result for item in security.authentication_results.results],
            "Authentication results are evaluated alongside observable infrastructure.",
            ["authentication", "structured_intelligence"], "medium",
        )
    return result


def _dedupe_correlations(items: list[Correlation]) -> list[Correlation]:
    merged: dict[tuple[str, str], Correlation] = {}
    for item in items:
        key = (item.code, item.relationship)
        if key not in merged:
            merged[key] = item
        else:
            current = merged[key]
            current.evidence = sorted(set(current.evidence).union(item.evidence))
            current.entities = sorted(set(current.entities).union(item.entities))
            current.sources = sorted(set(current.sources).union(item.sources))
    return sorted(merged.values(), key=lambda item: (item.code, item.relationship, item.entities))


def _safe_properties(properties: dict[str, Any] | None) -> dict[str, str | int | float | bool | None]:
    if not properties:
        return {}
    result: dict[str, str | int | float | bool | None] = {}
    for key, value in properties.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[str(key)] = value
    return result


_PROVIDER_FIELDS = {
    # Reputation and abuse
    "abuseConfidenceScore",
    "abuse_confidence_score",
    "abuse_score",
    "abuseScore",
    "lastReportedAt",
    "last_analysis_stats",
    "last_analysis_date",
    "reputation",
    "score",
    "totalReports",
    "isWhitelisted",
    # Routing, ownership, and network context
    "asn",
    "as_number",
    "network",
    "isp",
    "organization",
    "org",
    "as_owner",
    "usageType",
    # Geolocation
    "continent",
    "continent_code",
    "continent_name",
    "country",
    "country_code",
    "country_code2",
    "country_name",
    "region",
    "state_prov",
    "city",
    "postal_code",
    "zipcode",
    "latitude",
    "longitude",
    "timezone",
    "time_zone",
    # DNS records
    "addresses",
    "mx",
    "ns",
    "txt",
    "spf",
    "dmarc",
    "record_errors",
    "dns_records",
    "records",
    # RDAP registration
    "handle",
    "name",
    "ldhName",
    "unicodeName",
    "status",
    "events",
    "registrar",
    "nameservers",
    "registration_date",
    "expiration_date",
    "last_updated",
    "dnssec",
    "rdap",
    "registration",
    "registration_data",
    "geo",
    "geolocation",
}
_SENSITIVE_FIELD_RE = re.compile(
    r"(?:api[_-]?key|secret|password|passwd|token|credential|private[_-]?key|authorization)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def _provider_metadata(observation: Any) -> dict[str, str | int | float | bool | None]:
    """Flatten allow-listed provider fields onto an observable node.

    Provider payloads are normalized before this point, but graph properties
    must still be scalar and must not become a side channel for message data
    or credentials.
    """
    properties: dict[str, Any] = {
        "provider": observation.provider,
        "source": observation.provider,
        "confidence": observation.confidence,
        "observation_kind": observation.kind,
        "observation_status": observation.status,
    }
    data = observation.data if isinstance(observation.data, dict) else {}
    for field, value in data.items():
        field_name = str(field)
        if field_name not in _PROVIDER_FIELDS or _SENSITIVE_FIELD_RE.search(field_name):
            continue
        safe_value = _flatten_provider_value(value)
        if safe_value is not None:
            properties[field_name] = safe_value
    return _safe_properties(properties)


def _flatten_provider_value(value: Any) -> str | int | float | bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, str)):
        return _redact_provider_text(value) if isinstance(value, str) else value
    if isinstance(value, (list, tuple, dict)):
        redacted = _redact_provider_structure(value)
        try:
            return json.dumps(redacted, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return None
    return None


def _redact_provider_structure(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _redact_provider_structure(item)
            for key, item in value.items()
            if not _SENSITIVE_FIELD_RE.search(str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_redact_provider_structure(item) for item in value]
    if isinstance(value, str):
        return _redact_provider_text(value)
    return value


def _redact_provider_text(value: str) -> str:
    return _EMAIL_RE.sub("[redacted-email]", value)[:2000]


def _add_observation_properties(
    node: Any,
    add_edge: Any,
    edges: dict[tuple[str, str, str], EvidenceGraphEdge],
    entity_id: str,
    observation: Any,
) -> None:
    """Expose provider fields as graph nodes/edges without copying raw payloads."""
    data = observation.data if isinstance(observation.data, dict) else {}
    observation_id = f"provider:{observation.provider}:{observation.entity_type}:{observation.entity}:{observation.kind}".lower()
    for field, node_type, relationship in (
        ("asn", "asn", "announced_by"),
        ("country_code", "location", "located_in"),
        ("country", "location", "located_in"),
        ("region", "location", "located_in"),
        ("city", "location", "located_in"),
        ("isp", "provider", "served_by"),
        ("organization", "provider", "served_by"),
    ):
        value = data.get(field)
        if value:
            target_id = node(node_type, str(value), [observation.provider], {"field": field})
            add_edge(
                edges, entity_id, target_id, relationship, [observation.provider],
                [observation.entity, str(value)], _normalize_confidence(observation.confidence),
                {"field": field},
            )


def _normalize_confidence(value: str) -> Confidence:
    return cast(Confidence, value if value in {"high", "medium", "low", "unknown"} else "unknown")


def _indicator_confidence(severity: str) -> Confidence:
    return "high" if severity in {"high", "critical"} else "medium" if severity == "medium" else "low"


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def add_edge(
    edges: dict[tuple[str, str, str], EvidenceGraphEdge],
    source: str,
    target: str,
    relationship: str,
    providers: list[str],
    evidence: list[str],
    confidence: str,
    properties: dict[str, Any] | None = None,
) -> None:
    key = (source, target, relationship)
    if key not in edges:
        edges[key] = EvidenceGraphEdge(
            source=source,
            target=target,
            relationship=relationship,
            providers=sorted(set(providers)),
            evidence=sorted(set(evidence)),
            confidence=cast(Confidence, confidence),
            properties=_safe_properties(properties),
        )
    else:
        edges[key].providers = sorted(set(edges[key].providers).union(providers))
        edges[key].evidence = sorted(set(edges[key].evidence).union(evidence))
        edges[key].properties.update(_safe_properties(properties))


correlate_evidence = build_evidence_graph

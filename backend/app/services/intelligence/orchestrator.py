from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from app.config import Settings, get_settings
from app.schemas.email import EmailAnalysisResponse, RelayAnalysis
from app.schemas.security import SecurityAnalysis
from app.schemas.threat_intelligence import (
    EntityType,
    ProviderStatus,
    ThreatEntity,
    ThreatIntelligence,
    ThreatObservation,
    ThreatRelationship,
)
from app.services.intelligence.providers import ProviderRun, providers_from_settings
from app.services.url_extractor import extract_urls_and_domains


class ThreatIntelligenceOrchestrator:
    """Collects independent provider results and normalizes them per request."""

    def __init__(
        self,
        settings: Settings | None = None,
        providers: list[object] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.providers = providers if providers is not None else providers_from_settings(self.settings)
        # This cache intentionally belongs to one orchestrator/request. It never
        # persists observables or provider responses across email requests.
        self._request_cache: dict[tuple[str, str, str], object] = {}

    def analyze(
        self,
        email: EmailAnalysisResponse,
        relay_analysis: RelayAnalysis | None = None,
        security_analysis: SecurityAnalysis | None = None,
    ) -> ThreatIntelligence:
        self._request_cache.clear()
        if relay_analysis is None:
            from app.services.relay_analyzer import analyze_received_headers

            relay_analysis = analyze_received_headers(email.received)
        entities, _ = self._extract_entities(email, relay_analysis, security_analysis)
        entity_pairs = [(item.type, item.value) for item in entities]
        observations: list[ThreatObservation] = []
        relationships: list[ThreatRelationship] = []
        statuses: list[ProviderStatus] = []

        for provider in self.providers:
            name = str(getattr(provider, "name", provider.__class__.__name__.lower()))
            try:
                run = self._collect(provider, entity_pairs)
            except Exception:
                # Providers are isolation boundaries: one bad integration cannot
                # prevent the local result or another provider from completing.
                run = ProviderRun(name, "error", message="Provider unavailable")
            observations.extend(run.observations)
            relationships.extend(run.relationships)
            statuses.append(
                ProviderStatus(
                    provider=run.provider,
                    configured=run.status != "skipped" or run.message != "API key not configured",
                    status=run.status,
                    checked=self._checked_count(run, entity_pairs),
                    message=run.message,
                )
            )

        return ThreatIntelligence(
            entities=entities,
            observations=self._dedupe_observations(observations),
            relationships=self._dedupe_relationships(
                [*relationships, *self._correlate(entities, observations)]
            ),
            provider_status=statuses,
        )

    def _collect(self, provider: object, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        # Providers can be replaced with simple test doubles. The cache wraps
        # lookup calls while preserving the normal collect API for real providers.
        collect = getattr(provider, "collect", None)
        if collect is not None:
            name = str(getattr(provider, "name", provider.__class__.__name__))
            cache_key = (name, "run", repr(tuple(entities)))
            if cache_key not in self._request_cache:
                self._request_cache[cache_key] = collect(entities)
            return self._request_cache[cache_key]  # type: ignore[return-value]
        observations: list[ThreatObservation] = []
        relationships: list[ThreatRelationship] = []
        failures = 0
        for entity_type, entity in entities:
            key = (str(getattr(provider, "name", provider.__class__.__name__)), entity_type, entity)
            if key in self._request_cache:
                result = self._request_cache[key]
            else:
                try:
                    result = getattr(provider, "lookup")(entity_type, entity)
                except Exception:
                    failures += 1
                    continue
                self._request_cache[key] = result
            if isinstance(result, ThreatObservation):
                observations.append(result)
            elif isinstance(result, tuple) and result and isinstance(result[0], ThreatObservation):
                observations.append(result[0])
                if len(result) > 1 and isinstance(result[1], list):
                    relationships.extend(result[1])
        if not observations and failures:
            status = "error"
            message = "Provider unavailable"
        else:
            status = "degraded" if failures else "available"
            message = "Some lookups failed" if failures else None
        return ProviderRun(str(getattr(provider, "name", provider.__class__.__name__)), status, observations, relationships, message)

    @staticmethod
    def _checked_count(run: ProviderRun, entities: list[tuple[EntityType, str]]) -> int:
        if run.status == "skipped":
            return 0
        if run.checked:
            return run.checked
        return len({(item.entity_type, item.entity) for item in run.observations})

    @staticmethod
    def _extract_entities(
        email: EmailAnalysisResponse,
        relay_analysis: RelayAnalysis | None,
        security_analysis: SecurityAnalysis | None,
    ) -> tuple[list[ThreatEntity], dict[tuple[EntityType, str], set[str]]]:
        sources: dict[tuple[EntityType, str], set[str]] = {}

        def add(entity_type: EntityType, value: str | None, source: str) -> None:
            normalized = _normalize(entity_type, value)
            if normalized:
                sources.setdefault((entity_type, normalized), set()).add(source)

        if relay_analysis:
            for item in relay_analysis.extracted_ips:
                add("ip", item.address, "received")
            for hop in relay_analysis.relay_hops:
                for hostname in hop.hostnames:
                    add("domain", hostname, "received")

        url_analysis = security_analysis.url_analysis if security_analysis else None
        if url_analysis is None:
            url_analysis = extract_urls_and_domains(
                body_text=email.body_text,
                body_html=email.body_html,
                headers=(*email.received, email.from_, email.reply_to, email.return_path),
            )
        for item in url_analysis.urls:
            add("url", item.normalized_url, item.source)
            if _normalize("ip", item.domain):
                add("ip", item.domain, "url")
            else:
                add("domain", item.domain, "url")
        for item in url_analysis.domains:
            add("domain", item.domain, item.source)

        for value, source in (
            (email.from_, "from"),
            (email.reply_to, "reply_to"),
            (email.return_path, "return_path"),
        ):
            if value and "@" in value:
                add("domain", value.rsplit("@", 1)[-1].strip(" >."), source)
        if security_analysis:
            for item in security_analysis.domains:
                add("domain", item.domain, item.source)
            auth = security_analysis.authentication_results
            for value, source in (
                (auth.from_domain, "authentication"),
                (auth.return_path_domain, "authentication"),
                (auth.reply_to_domain, "authentication"),
                (auth.dkim.domain if auth.dkim else None, "dkim"),
                (auth.dmarc.domain if auth.dmarc else None, "dmarc"),
            ):
                add("domain", value, source)

        entities = [
            ThreatEntity(type=entity_type, value=value, sources=sorted(entity_sources))
            for (entity_type, value), entity_sources in sorted(sources.items())
        ]
        return entities, sources

    @staticmethod
    def _dedupe_observations(items: Iterable[ThreatObservation]) -> list[ThreatObservation]:
        result: list[ThreatObservation] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in items:
            key = (item.provider, item.entity_type, item.entity, item.kind)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    @staticmethod
    def _dedupe_relationships(items: Iterable[ThreatRelationship]) -> list[ThreatRelationship]:
        merged: dict[tuple[str, str, str, str, str], ThreatRelationship] = {}
        for item in items:
            key = (item.source_type, item.source, item.target_type, item.target, item.relationship)
            if key not in merged:
                merged[key] = item
            else:
                merged[key].providers = sorted(
                    set(merged[key].providers).union(item.providers)
                )
        return list(merged.values())

    @staticmethod
    def _correlate(
        entities: list[ThreatEntity], observations: list[ThreatObservation]
    ) -> list[ThreatRelationship]:
        relationships: list[ThreatRelationship] = []
        domains = {item.value for item in entities if item.type == "domain"}
        urls = {item.value for item in entities if item.type == "url"}
        for url in urls:
            try:
                domain = urlsplit(url).hostname
            except ValueError:
                domain = None
            if domain and domain.lower().rstrip(".") in domains:
                relationships.append(
                    ThreatRelationship(
                        source_type="url",
                        source=url,
                        target_type="domain",
                        target=domain.lower().rstrip("."),
                        relationship="hosted_by",
                        providers=["local_correlation"],
                    )
                )
        return relationships


def analyze_threat_intelligence(
    email: EmailAnalysisResponse,
    relay_analysis: RelayAnalysis | None = None,
    security_analysis: SecurityAnalysis | None = None,
) -> ThreatIntelligence:
    return ThreatIntelligenceOrchestrator().analyze(email, relay_analysis, security_analysis)


def _normalize(entity_type: EntityType, value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if entity_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if entity_type == "domain":
        value = value.lower().rstrip(".")
        if not value or " " in value or "." not in value or _normalize("ip", value):
            return None
        return value
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ftp"} or not parsed.hostname:
            return None
        return value.lower().rstrip("#")
    except ValueError:
        return None

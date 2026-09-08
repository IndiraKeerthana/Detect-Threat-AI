from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass, field
import re
from typing import Any

from app.config import Settings
from app.schemas.threat_intelligence import (
    EntityType,
    ProviderState,
    ThreatObservation,
    ThreatRelationship,
)

_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


@dataclass
class ProviderRun:
    provider: str
    status: ProviderState
    observations: list[ThreatObservation] = field(default_factory=list)
    relationships: list[ThreatRelationship] = field(default_factory=list)
    message: str | None = None
    checked: int = 0


def _observation(
    provider: str,
    entity_type: EntityType,
    entity: str,
    kind: str,
    data: dict[str, Any] | None = None,
    evidence: list[str] | None = None,
    status: str = "success",
) -> ThreatObservation:
    return ThreatObservation(
        provider=provider,
        entity_type=entity_type,
        entity=entity,
        kind=kind,
        status=status,
        data=data or {},
        evidence=evidence or [],
        retrieved_at=datetime.now(timezone.utc).isoformat(),
        confidence="high" if status == "success" else "none",
    )


class LocalIPClassifierProvider:
    name = "local_ip_classification"

    @staticmethod
    def classify(value: str) -> dict[str, Any] | None:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if any(address in network for network in _DOCUMENTATION_NETWORKS):
            classification = "documentation_or_test"
        elif address.is_loopback:
            classification = "loopback"
        elif address.is_link_local:
            classification = "link_local"
        elif address.is_private:
            classification = "private"
        elif address.is_multicast:
            classification = "multicast"
        elif address.is_unspecified:
            classification = "unspecified"
        elif address.is_reserved:
            classification = "reserved"
        else:
            classification = "public"
        return {
            "address": str(address),
            "version": address.version,
            "classification": classification,
            "is_public": classification == "public",
            "is_public_source_candidate": classification == "public",
        }

    def lookup(self, entity_type: EntityType, entity: str) -> ThreatObservation | None:
        if entity_type != "ip":
            return None
        data = self.classify(entity)
        if not data:
            return None
        if not data["is_public"]:
            data = {
                **data,
                "enrichment_status": "skipped",
                "enrichment_reason": "Non-public, private, loopback, link-local, multicast, reserved, or documentation IP.",
            }
        return _observation(self.name, "ip", entity, "classification", data, [entity])

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        observations = [
            result
            for entity_type, entity in entities
            if (result := self.lookup(entity_type, entity)) is not None
        ]
        return ProviderRun(self.name, "available", observations)


class _HTTPProvider:
    timeout: float

    def _json(self, request: urllib.request.Request) -> tuple[int, Any]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status_value = getattr(response, "status", None)
                status = int(status_value if status_value is not None else response.getcode())
                payload = json.loads(response.read().decode("utf-8"))
                return status, payload
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise RuntimeError("provider request failed") from exc
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("provider returned malformed data") from exc


class AbuseIPDBProvider(_HTTPProvider):
    name = "abuseipdb"

    def __init__(self, api_key: str | None, timeout: float = 2.0) -> None:
        self.api_key = api_key.strip() if api_key else None
        self.timeout = timeout

    def lookup(self, entity_type: EntityType, entity: str) -> ThreatObservation | None:
        if entity_type != "ip" or not self.api_key:
            return None
        request = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/check?"
            + urllib.parse.urlencode({"ipAddress": entity}),
            headers={"Accept": "application/json", "Key": self.api_key or ""},
        )
        status, payload = self._json(request)
        if status < 200 or status >= 300 or not isinstance(payload, dict):
            raise ValueError("provider returned malformed data")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("provider returned malformed data")
        allowed = (
            "abuseConfidenceScore",
            "totalReports",
            "lastReportedAt",
            "isWhitelisted",
            "countryCode",
            "usageType",
            "isp",
            "domain",
        )
        normalized = {key: data[key] for key in allowed if key in data}
        if not normalized:
            raise ValueError("provider returned malformed data")
        return _observation(self.name, "ip", entity, "reputation", normalized, [entity])

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        if not self.api_key:
            return ProviderRun(self.name, "skipped", message="API key not configured")
        return _collect_http_provider(self, entities)


class VirusTotalProvider(_HTTPProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None, timeout: float = 2.0) -> None:
        self.api_key = api_key.strip() if api_key else None
        self.timeout = timeout

    def lookup(self, entity_type: EntityType, entity: str) -> ThreatObservation | None:
        if entity_type not in {"ip", "domain"} or not self.api_key:
            return None
        encoded = urllib.parse.quote(entity, safe="")
        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{entity_type}s/{encoded}",
            headers={"Accept": "application/json", "x-apikey": self.api_key or ""},
        )
        status, payload = self._json(request)
        if status < 200 or status >= 300 or not isinstance(payload, dict):
            raise ValueError("provider returned malformed data")
        attributes = payload.get("data", {}).get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("provider returned malformed data")
        allowed = (
            "last_analysis_stats",
            "reputation",
            "last_analysis_date",
            "country",
            "as_owner",
            "network",
        )
        normalized = {key: attributes[key] for key in allowed if key in attributes}
        if not normalized:
            raise ValueError("provider returned malformed data")
        return _observation(self.name, entity_type, entity, "reputation", normalized, [entity])

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        if not self.api_key:
            return ProviderRun(self.name, "skipped", message="API key not configured")
        return _collect_http_provider(self, entities)


def _collect_http_provider(provider: Any, entities: list[tuple[EntityType, str]]) -> ProviderRun:
    observations: list[ThreatObservation] = []
    failures = 0
    checked = {(kind, value) for kind, value in entities}
    eligible: list[tuple[EntityType, str]] = []
    for entity_type, entity in sorted(checked):
        if entity_type not in {"ip", "domain"}:
            continue
        if entity_type == "ip":
            classification = LocalIPClassifierProvider.classify(entity)
            if not classification or not classification["is_public"]:
                continue
        eligible.append((entity_type, entity))
        try:
            result = provider.lookup(entity_type, entity)
            if result:
                observations.append(result)
        except (RuntimeError, ValueError, TypeError):
            failures += 1
    if failures and not observations:
        return ProviderRun(
            provider.name,
            "error",
            message="Provider unavailable or returned invalid data",
            checked=len(eligible),
        )
    return ProviderRun(
        provider.name,
        "degraded" if failures else "available",
        observations,
        message="Some lookups failed" if failures else None,
        checked=len(eligible),
    )


class IPGeolocationProvider(_HTTPProvider):
    """Geolocate public IP observables without sending non-public addresses."""

    name = "geolocation"
    _FIELDS = (
        "ip",
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
        "isp",
        "organization",
        "asn",
    )

    def __init__(self, api_key: str | None, timeout: float = 2.0) -> None:
        self.api_key = api_key.strip() if api_key else None
        self.timeout = timeout

    @staticmethod
    def _first(payload: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = payload.get(key)
            if value is not None and value != "":
                return value
        return None

    @staticmethod
    def _number(value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _normalize(self, entity: str, payload: dict[str, Any]) -> dict[str, Any]:
        location = payload.get("location")
        if not isinstance(location, dict):
            location = {}
        asn = payload.get("asn")
        if not isinstance(asn, dict):
            asn = {}
        timezone = payload.get("time_zone")
        if isinstance(timezone, dict):
            timezone = self._first(timezone, "name", "timezone")
        elif not isinstance(timezone, str):
            timezone = None
        asn_value = self._first(asn, "as_number", "number", "asn") or self._first(
            payload, "asn"
        )
        if isinstance(asn_value, dict):
            asn_value = None
        organization = (
            self._first(payload, "organization", "asn_org")
            or self._first(asn, "organization", "org")
        )
        normalized = {
            "ip": self._first(payload, "ip") or entity,
            "continent": self._first(location, "continent_name", "continent"),
            "continent_code": self._first(location, "continent_code"),
            "continent_name": self._first(location, "continent_name", "continent"),
            "country": self._first(location, "country_name", "country"),
            "country_code": self._first(location, "country_code2", "country_code"),
            "country_code2": self._first(location, "country_code2", "country_code"),
            "country_name": self._first(location, "country_name", "country"),
            "region": self._first(location, "state_prov", "region", "state"),
            "state_prov": self._first(location, "state_prov", "region", "state"),
            "city": self._first(location, "city"),
            "postal_code": self._first(location, "zipcode", "postal_code"),
            "zipcode": self._first(location, "zipcode", "postal_code"),
            "latitude": self._number(self._first(location, "latitude", "lat")),
            "longitude": self._number(self._first(location, "longitude", "lon", "lng")),
            "timezone": timezone,
            "time_zone": timezone,
            "isp": self._first(payload, "isp", "internet_service_provider"),
            "organization": organization,
            "asn": asn_value,
        }
        return {field: normalized[field] for field in self._FIELDS}

    def lookup(
        self, entity_type: EntityType, entity: str
    ) -> tuple[ThreatObservation, list[ThreatRelationship]] | None:
        classification = (
            LocalIPClassifierProvider.classify(entity) if entity_type == "ip" else None
        )
        if not self.api_key or not classification or not classification["is_public"]:
            return None
        request = urllib.request.Request(
            "https://api.ipgeolocation.io/v3/ipgeo?"
            + urllib.parse.urlencode({"apiKey": self.api_key, "ip": entity}),
            headers={"Accept": "application/json"},
            method="GET",
        )
        status, payload = self._json(request)
        if status < 200 or status >= 300 or not isinstance(payload, dict):
            raise ValueError("provider returned malformed data")
        normalized = self._normalize(entity, payload)
        evidence = [entity]
        relationships: list[ThreatRelationship] = []
        country = normalized["country_code"] or normalized["country"]
        if country:
            relationships.append(
                ThreatRelationship(
                    source_type="ip",
                    source=entity,
                    target_type="country",
                    target=str(country),
                    relationship="located_in",
                    providers=[self.name],
                )
            )
        region = normalized["region"]
        if region:
            relationships.append(
                ThreatRelationship(
                    source_type="ip",
                    source=entity,
                    target_type="region",
                    target=str(region),
                    relationship="located_in",
                    providers=[self.name],
                )
            )
        city = normalized["city"]
        if city:
            relationships.append(
                ThreatRelationship(
                    source_type="ip",
                    source=entity,
                    target_type="city",
                    target=str(city),
                    relationship="located_in",
                    providers=[self.name],
                )
            )
        asn = normalized["asn"]
        if asn:
            relationships.append(
                ThreatRelationship(
                    source_type="ip",
                    source=entity,
                    target_type="asn",
                    target=str(asn),
                    relationship="announced_by",
                    providers=[self.name],
                )
            )
        return _observation(
            self.name,
            "ip",
            entity,
            "geolocation",
            normalized,
            evidence,
        ), relationships

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        if not self.api_key:
            return ProviderRun(self.name, "skipped", message="API key not configured")
        observations: list[ThreatObservation] = []
        relationships: list[ThreatRelationship] = []
        failures = 0
        eligible = {
            (entity_type, entity)
            for entity_type, entity in entities
            if entity_type == "ip"
            and (classification := LocalIPClassifierProvider.classify(entity))
            and classification["is_public"]
        }
        for _, entity in sorted(eligible):
            try:
                result = self.lookup("ip", entity)
                if result:
                    observation, links = result
                    observations.append(observation)
                    relationships.extend(links)
            except (RuntimeError, ValueError, TypeError):
                failures += 1
        if failures and not observations:
            return ProviderRun(
                self.name,
                "error",
                relationships=relationships,
                message="Provider unavailable or returned invalid data",
                checked=len(eligible),
            )
        return ProviderRun(
            self.name,
            "available",
            observations,
            relationships,
            message="Some lookups failed" if failures else None,
            checked=len(eligible),
        )


class DNSProvider:
    name = "dns"
    _RECORD_TYPES = {
        "MX": 15,
        "NS": 2,
        "TXT": 16,
        "SPF": 99,
    }

    def __init__(self, enabled: bool = True, timeout: float = 1.0) -> None:
        self.enabled = enabled
        self.timeout = timeout

    @staticmethod
    def _dns_name(name: str) -> bytes:
        labels = name.rstrip(".").split(".")
        return b"".join(bytes([len(label)]) + label.encode("idna") for label in labels) + b"\0"

    @staticmethod
    def _read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        cursor = offset
        next_offset = offset
        jumped = False
        while cursor < len(packet):
            length = packet[cursor]
            if length == 0:
                if not jumped:
                    next_offset = cursor + 1
                break
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(packet):
                    raise ValueError("invalid compressed DNS name")
                pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
                if not jumped:
                    next_offset = cursor + 2
                cursor = pointer
                jumped = True
                continue
            cursor += 1
            end = cursor + length
            if end > len(packet):
                raise ValueError("invalid DNS name")
            labels.append(packet[cursor:end].decode("idna"))
            cursor = end
            if not jumped:
                next_offset = cursor
        else:
            raise ValueError("unterminated DNS name")
        return ".".join(labels).rstrip("."), next_offset

    @staticmethod
    def _nameservers() -> list[str]:
        # Keep the resolver dependency-free. The environment override also
        # makes this deterministic for offline deployments and tests.
        configured = os.getenv("DNS_NAMESERVERS", "")
        if configured:
            return [item.strip() for item in configured.split(",") if item.strip()]
        return ["8.8.8.8"]

    def _resolve_record(self, name: str, record_type: str) -> list[Any]:
        query_id = os.urandom(2)
        packet = (
            query_id
            + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
            + self._dns_name(name)
            + struct.pack("!HH", self._RECORD_TYPES[record_type], 1)
        )
        last_error: Exception | None = None
        for nameserver in self._nameservers():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(packet, (nameserver, 53))
                    response, _ = sock.recvfrom(4096)
                if len(response) < 12 or response[:2] != query_id:
                    raise ValueError("invalid DNS response")
                flags, questions, answer_count = struct.unpack("!HHH", response[2:8])
                if flags & 0x000F:
                    return []
                offset = 12
                for _ in range(questions):
                    _, offset = self._read_dns_name(response, offset)
                    offset += 4
                values: list[Any] = []
                for _ in range(answer_count):
                    _, offset = self._read_dns_name(response, offset)
                    if offset + 10 > len(response):
                        raise ValueError("truncated DNS answer")
                    answer_type, answer_class, _, data_length = struct.unpack(
                        "!HHIH", response[offset : offset + 10]
                    )
                    offset += 10
                    data_end = offset + data_length
                    if data_end > len(response):
                        raise ValueError("truncated DNS record")
                    if answer_class != 1 or answer_type != self._RECORD_TYPES[record_type]:
                        offset = data_end
                        continue
                    if record_type == "A" and data_length == 4:
                        values.append(str(ipaddress.ip_address(response[offset:data_end])))
                    elif record_type == "AAAA" and data_length == 16:
                        values.append(str(ipaddress.ip_address(response[offset:data_end])))
                    elif record_type in {"NS", "SPF"}:
                        if record_type == "NS":
                            values.append(self._read_dns_name(response, offset)[0])
                        else:
                            values.append(response[offset:data_end].decode("utf-8", "replace"))
                    elif record_type == "MX" and data_length >= 3:
                        preference = struct.unpack("!H", response[offset : offset + 2])[0]
                        exchange = self._read_dns_name(response, offset + 2)[0]
                        values.append({"preference": preference, "exchange": exchange})
                    elif record_type == "TXT":
                        cursor = offset
                        parts: list[str] = []
                        while cursor < data_end:
                            length = response[cursor]
                            cursor += 1
                            parts.append(response[cursor : cursor + length].decode("utf-8", "replace"))
                            cursor += length
                        values.append("".join(parts))
                    offset = data_end
                return values
            except (OSError, TimeoutError, struct.error, UnicodeError, ValueError) as exc:
                last_error = exc
        if last_error:
            raise RuntimeError("DNS record lookup failed") from last_error
        return []

    def lookup(self, entity_type: EntityType, entity: str) -> tuple[ThreatObservation, list[str]] | None:
        if entity_type != "domain" or not self.enabled:
            return None
        record_errors: list[str] = []
        try:
            addresses = {
                str(info[4][0])
                for info in socket.getaddrinfo(entity, None, type=socket.SOCK_STREAM)
                if info[4] and info[4][0]
            }
        except (socket.gaierror, OSError, ValueError, TypeError):
            addresses = set()
            record_errors.append("A/AAAA")
        valid = [
            address
            for address in sorted(addresses)
            if LocalIPClassifierProvider.classify(address)
        ]
        records: dict[str, Any] = {
            "addresses": valid,
            "a": [address for address in valid if ipaddress.ip_address(address).version == 4],
            "aaaa": [address for address in valid if ipaddress.ip_address(address).version == 6],
            "mx": [],
            "ns": [],
            "txt": [],
            "spf": [],
            "dmarc": [],
        }
        raw_txt: list[str] = []
        raw_dmarc: list[str] = []
        for record_type, key, name in (
            ("MX", "mx", entity),
            ("NS", "ns", entity),
            ("TXT", "txt", entity),
            ("TXT", "_spf", entity),
            ("TXT", "_dmarc", f"_dmarc.{entity}"),
        ):
            try:
                values = self._resolve_record(name, record_type)
                if key == "txt":
                    raw_txt = [value for value in values if isinstance(value, str)]
                elif key == "_spf":
                    records["spf"] = [
                        value for value in values
                        if isinstance(value, str) and value.lower().startswith("v=spf1")
                    ]
                elif key == "_dmarc":
                    raw_dmarc = [
                        value for value in values
                        if isinstance(value, str) and value.lower().startswith("v=dmarc1")
                    ]
                else:
                    records[key] = values
            except Exception:
                record_errors.append(key)
        records["txt"] = raw_txt
        records["dmarc"] = self._normalize_dmarc(raw_dmarc)
        if record_errors:
            records["record_errors"] = sorted(set(record_errors))
        relationships = [
            ThreatRelationship(
                source_type="domain",
                source=entity,
                target_type="ip",
                target=address,
                relationship="resolves_to",
                providers=[self.name],
            )
            for address in valid
        ]
        evidence = valid + [
            str(value)
            for key in ("mx", "ns", "txt", "spf", "dmarc")
            for value in records[key]
        ]
        return _observation(self.name, "domain", entity, "dns", records, evidence), [
            relationship for relationship in relationships
        ]

    @staticmethod
    def _normalize_dmarc(values: list[str]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for value in values:
            tags = {
                key.lower(): item.strip()
                for key, item in re.findall(r"(?:^|;)\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*([^;]*)", value)
            }
            normalized.append(
                {
                    "record": value,
                    "policy": tags.get("p"),
                    "subdomain_policy": tags.get("sp"),
                    "aggregate_reporting": tags.get("rua"),
                }
            )
        return normalized

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        if not self.enabled:
            return ProviderRun(self.name, "skipped", message="Provider disabled")
        observations: list[ThreatObservation] = []
        relationships: list[ThreatRelationship] = []
        failures = 0
        eligible = {
            (entity_type, entity) for entity_type, entity in entities if entity_type == "domain"
        }
        for entity_type, entity in sorted(eligible):
            result = None
            try:
                result = self.lookup(entity_type, entity)
                if result:
                    observation, links = result
                    observations.append(observation)
                    relationships.extend(links)
            except (IndexError, socket.gaierror, OSError, ValueError, TypeError):
                failures += 1
            if result and result[0].data.get("record_errors"):
                failures += 1
        if failures and not observations:
            return ProviderRun(self.name, "error", message="DNS lookup failed")
        return ProviderRun(
            self.name,
            "available",
            observations,
            relationships,
            message="Some DNS record lookups failed" if failures else None,
            checked=len(eligible),
        )


class RDAPProvider(_HTTPProvider):
    name = "rdap"

    def __init__(self, enabled: bool = True, timeout: float = 2.0) -> None:
        self.enabled = enabled
        self.timeout = timeout

    def lookup(self, entity_type: EntityType, entity: str) -> ThreatObservation | None:
        if entity_type not in {"ip", "domain"} or not self.enabled:
            return None
        path = "ip" if entity_type == "ip" else "domain"
        request = urllib.request.Request(
            f"https://rdap.org/{path}/{urllib.parse.quote(entity, safe='')}",
            headers={"Accept": "application/rdap+json, application/json"},
        )
        status, payload = self._json(request)
        if status < 200 or status >= 300 or not isinstance(payload, dict):
            raise ValueError("provider returned malformed data")
        normalized: dict[str, Any] = {}
        for key in ("handle", "name", "ldhName", "unicodeName", "country", "status"):
            if key in payload and isinstance(payload[key], (str, list)):
                normalized[key] = payload[key]
        events = payload.get("events")
        if isinstance(events, list):
            normalized["events"] = [
                {"eventAction": item.get("eventAction"), "eventDate": item.get("eventDate")}
                for item in events
                if isinstance(item, dict) and isinstance(item.get("eventAction"), str)
            ]
            event_dates = {
                str(item.get("eventAction", "")).lower().replace(" ", "_"): item.get("eventDate")
                for item in events
                if isinstance(item, dict)
                and isinstance(item.get("eventAction"), str)
                and isinstance(item.get("eventDate"), str)
            }
            for action, key in (
                ("registration", "registration_date"),
                ("expiration", "expiration_date"),
                ("last_changed", "last_updated"),
                ("last_update", "last_updated"),
                ("last_updated", "last_updated"),
                ("last_update_of_rdap_database", "last_updated"),
            ):
                if event_dates.get(action) and key not in normalized:
                    normalized[key] = event_dates[action]

        entities = payload.get("entities")
        if isinstance(entities, list):
            for item in entities:
                if not isinstance(item, dict) or "registrar" not in [
                    str(role).lower() for role in item.get("roles", [])
                ]:
                    continue
                registrar = self._vcard_value(item.get("vcardArray"), "fn", "org")
                if registrar:
                    normalized["registrar"] = registrar
                    break
        if "registrar" not in normalized and isinstance(payload.get("registrar"), str):
            normalized["registrar"] = payload["registrar"]

        nameservers = payload.get("nameservers", payload.get("nameServers"))
        if isinstance(nameservers, list):
            normalized["nameservers"] = list(
                dict.fromkeys(
                    value
                    for item in nameservers
                    if isinstance(item, dict)
                    for value in (
                        (
                            item.get("ldhName") or item.get("unicodeName")
                        ).lower().rstrip(".")
                        if isinstance(item.get("ldhName") or item.get("unicodeName"), str)
                        else None,
                    )
                    if isinstance(value, str) and value
                )
            )

        secure_dns = payload.get("secureDNS")
        if isinstance(secure_dns, dict):
            normalized["dnssec"] = secure_dns
        if not normalized:
            raise ValueError("provider returned malformed data")
        return _observation(self.name, entity_type, entity, "registration", normalized, [entity])

    @staticmethod
    def _vcard_value(vcard: Any, *properties: str) -> str | None:
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            return None
        wanted = {property_name.lower() for property_name in properties}
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if str(item[0]).lower() in wanted and isinstance(item[3], str):
                return item[3]
        return None

    def collect(self, entities: list[tuple[EntityType, str]]) -> ProviderRun:
        if not self.enabled:
            return ProviderRun(self.name, "skipped", message="Provider disabled")
        return _collect_http_provider(self, entities)


def providers_from_settings(settings: Settings) -> list[Any]:
    return [
        LocalIPClassifierProvider(),
        AbuseIPDBProvider(settings.abuseipdb_api_key, settings.threat_intelligence_timeout_seconds),
        VirusTotalProvider(settings.virustotal_api_key, settings.threat_intelligence_timeout_seconds),
        IPGeolocationProvider(
            settings.ip_geolocation_api_key, settings.threat_intelligence_timeout_seconds
        ),
        DNSProvider(
            settings.threat_intelligence_dns_enabled,
            settings.threat_intelligence_timeout_seconds,
        ),
        RDAPProvider(settings.threat_intelligence_rdap_enabled, settings.threat_intelligence_timeout_seconds),
    ]
